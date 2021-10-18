package ovndbmanager

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"k8s.io/client-go/kubernetes/fake"
)

type mockRes struct {
	res    string
	stderr string
	err    error
	called bool
}

const (
	status_template = `87f0
Name: %s
Cluster ID: f832 (f832bbff-e28c-4656-83f0-075e91a7ab8f)
Server ID: 87f0 (87f0d686-8a8d-4585-9513-45efac449101)
Address: %s
Status: cluster member
Role: %s
Term: 4
Leader: bbf6
Vote: unknown

Election timer: %s
Log: [19418, 26772]
Entries not yet committed: 0
Entries not yet applied: 0
Connections: ->bbf6 ->ad31 <-bbf6 <-ad31
Disconnections: 1
%s`

	serverAddress = "ssl:10.1.1.185:9643"

	servers = `Servers:
    87f0 (87f0 at ssl:10.1.1.185:9643) (self)
    bbf6 (bbf6 at ssl:10.1.1.218:9643) last msg 2757 ms ago
    ad31 (ad31 at ssl:10.1.1.211:9643) last msg 153868958 ms ago`

	staleServers = `Servers:
    87f0 (87f0 at ssl:10.1.1.185:9643) (self)
    3936 (3936 at ssl:10.1.1.185:9643) last msg 153868958 ms ago
    bbf6 (bbf6 at ssl:10.1.1.218:9643) last msg 2757 ms ago
    ad31 (ad31 at ssl:10.1.1.211:9643) last msg 153868958 ms ago`

	staleSid = "3936"

	unknownServers = `Servers:
    87f0 (87f0 at ssl:10.1.1.185:9643) (self)
    c10c (c10c at ssl:10.1.1.219:9643) last msg 2757 ms ago
    fc43 (fc43 at ssl:10.1.1.220:9643) last msg 2123 ms ago
    bbf6 (bbf6 at ssl:10.1.1.218:9643) last msg 1543 ms ago
    ad31 (ad31 at ssl:10.1.1.211:9643) last msg 153868958 ms ago`

	knownMembers = "ssl:10.1.1.185:9643,ssl:10.1.1.218:9643,ssl:10.1.1.211:9643"
)

var (
	unknownSids = [...]string{"c10c", "fc43"}
)

func TestEnsureLocalRaftServerID(t *testing.T) {
	var mockCalls map[string]*mockRes
	unexpectedKeys := make([]string, 0)
	mock := func(timeout int, args ...string) (string, string, error) {
		key := keyForArgs(args...)
		res, ok := mockCalls[key]
		if !ok {
			unexpectedKeys = append(unexpectedKeys, key)
			return "", "key not found", fmt.Errorf("key not found")
		}
		res.called = true
		return res.res, res.stderr, res.err
	}

	db := &dbProperties{
		appCtl: mock,
	}

	tests := []struct {
		desc        string
		dbAlias     string
		dbName      string
		mockCalls   map[string]*mockRes
		servers     string
		sid         string
		errorString string
	}{
		{
			desc:   "Test error: unable to get db server ID",
			dbName: "OVN_Northbound",
			mockCalls: map[string]*mockRes{
				keyForArgs("cluster/sid", "OVN_Northbound"): {
					res:    "",
					stderr: "failure",
					err:    fmt.Errorf("failure"),
				},
			},
			errorString: "unable to get db server ID for",
		},
		{
			desc:        "Test error: Invalid sid",
			dbName:      "OVN_Northbound",
			mockCalls:   map[string]*mockRes{},
			sid:         "87f",
			errorString: "invalid db id found",
		},
		{
			desc:   "Test error: Unable to get cluster status",
			dbName: "OVN_Northbound",
			mockCalls: map[string]*mockRes{
				keyForArgs("cluster/status", "OVN_Northbound"): {
					res:    "",
					stderr: "failure",
					err:    fmt.Errorf("failure"),
				},
			},
			sid:         "87f0d686-8a8d-4585-9513-45efac449101",
			errorString: "unable to get cluster status for",
		},
		{
			desc:   "Test error: unable to parse address for db",
			dbName: "OVN_Northbound",
			mockCalls: map[string]*mockRes{
				keyForArgs("cluster/status", "OVN_Northbound"): {
					res: fmt.Sprintf(
						status_template,
						"OVN_Northbound",
						"http://10.1.1.185:9643",
						"leader",
						"1000",
						servers),
					stderr: "",
					err:    nil,
				},
			},
			sid:         "87f0d686-8a8d-4585-9513-45efac449101",
			errorString: "unable to parse Address for db",
		},
		{
			desc:    "Test error: while kicking old Raft member",
			dbAlias: "ovnnb",
			dbName:  "OVN_Northbound",
			mockCalls: map[string]*mockRes{
				keyForArgs("cluster/kick", "OVN_Northbound", staleSid): {
					res:    "",
					stderr: "failure",
					err:    fmt.Errorf("failure"),
				},
			},
			servers:     staleServers,
			sid:         "87f0d686-8a8d-4585-9513-45efac449101",
			errorString: "error while kicking old Raft member",
		},
		{
			desc:    "Stale member, kick",
			dbAlias: "ovnnb",
			dbName:  "OVN_Northbound",
			mockCalls: map[string]*mockRes{
				keyForArgs("cluster/kick", "OVN_Northbound", staleSid): {
					res:    "started removal",
					stderr: "",
					err:    nil,
				},
			},
			servers: staleServers,
			sid:     "87f0d686-8a8d-4585-9513-45efac449101",
		},
		{
			desc:      "Consistent database, no action needed",
			dbAlias:   "ovnnb",
			dbName:    "OVN_Northbound",
			mockCalls: map[string]*mockRes{},
			servers:   servers,
			sid:       "87f0d686-8a8d-4585-9513-45efac449101",
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			// default mockCalls which may be supplemented or overwritten by
			// more specific tc mockCalls from the above maps
			mockCalls = map[string]*mockRes{
				keyForArgs("cluster/status", tc.dbName): {
					res: fmt.Sprintf(
						status_template,
						tc.dbName,
						serverAddress,
						"leader",
						"1000",
						tc.servers),
					stderr: "",
					err:    nil,
				},
				keyForArgs("cluster/sid", "OVN_Northbound"): {
					res:    tc.sid,
					stderr: "",
					err:    nil,
				},
			}
			for k, v := range tc.mockCalls {
				mockCalls[k] = v
			}

			db.dbName = tc.dbName
			db.dbAlias = tc.dbAlias

			err := ensureLocalRaftServerID(db)

			// fail either if an error is seen but not expected
			// or if an error is expected but when the subscring does not match the error
			failOnErrorMatch(t, err, tc.errorString)

			for k, c := range tc.mockCalls {
				if !c.called {
					t.Errorf("Expecting call with args %s", k)
				}
			}
			if len(unexpectedKeys) > 0 {
				t.Errorf("Received unexpected calls %v", unexpectedKeys)
			}
		})
	}
}

func TestEnsureClusterRaftMembership(t *testing.T) {
	var mockCalls map[string]*mockRes
	unexpectedKeys := make([]string, 0)

	mock := func(timeout int, args ...string) (string, string, error) {
		key := keyForArgs(args...)
		res, ok := mockCalls[key]
		if !ok {
			unexpectedKeys = append(unexpectedKeys, key)
			return "", "key not found", fmt.Errorf("key not found")
		}
		res.called = true
		return res.res, res.stderr, res.err
	}

	config.OvnNorth.Address = knownMembers
	config.OvnSouth.Address = knownMembers

	fakeClient := fake.NewSimpleClientset()
	kubeInterface := &kube.Kube{
		KClient: fakeClient,
	}

	db := &dbProperties{
		appCtl: mock,
	}
	tests := []struct {
		desc        string
		dbAlias     string
		dbName      string
		mockCalls   map[string]*mockRes
		servers     string
		sid         string
		errorString string
	}{
		{
			desc:        "Test error: Invalid database name",
			dbAlias:     "ovnnb",
			dbName:      "OVN_Northboundd",
			mockCalls:   map[string]*mockRes{},
			servers:     servers,
			errorString: "invalid database name",
		},
		{
			desc:   "Test error: Unable to get cluster status",
			dbName: "OVN_Northbound",
			mockCalls: map[string]*mockRes{
				keyForArgs("cluster/status", "OVN_Northbound"): {
					res:    "",
					stderr: "failure",
					err:    fmt.Errorf("failure"),
				},
			},
			sid:         "87f0d686-8a8d-4585-9513-45efac449101",
			errorString: "Unable to get cluster status for",
		},
		{
			desc:      "Consistent database, no action needed",
			dbAlias:   "ovnnb",
			dbName:    "OVN_Northbound",
			mockCalls: map[string]*mockRes{},
			servers:   servers,
			sid:       "87f0d686-8a8d-4585-9513-45efac449101",
		},
		{
			desc:    "Unknown Raft member, kick",
			dbAlias: "ovnnb",
			dbName:  "OVN_Northbound",
			mockCalls: map[string]*mockRes{
				keyForArgs("cluster/kick", "OVN_Northbound", unknownSids[0]): {
					res:    "started removal",
					stderr: "",
					err:    nil,
				},
				keyForArgs("cluster/kick", "OVN_Northbound", unknownSids[1]): {
					res:    "started removal",
					stderr: "",
					err:    nil,
				},
			},
			servers: unknownServers,
			sid:     "87f0d686-8a8d-4585-9513-45efac449101",
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			// default mockCalls which may be supplemented or overwritten by
			// more specific tc mockCalls from the above maps
			mockCalls = map[string]*mockRes{
				keyForArgs("cluster/status", tc.dbName): {
					res: fmt.Sprintf(
						status_template,
						tc.dbName,
						serverAddress,
						"leader",
						"1000",
						tc.servers),
					stderr: "",
					err:    nil,
				},
				keyForArgs("cluster/sid", tc.dbName): {
					res:    tc.sid,
					stderr: "",
					err:    nil,
				},
			}
			for k, v := range tc.mockCalls {
				mockCalls[k] = v
			}

			db.dbName = tc.dbName
			db.dbAlias = tc.dbAlias
			err := ensureClusterRaftMembership(db, kubeInterface)

			// fail either if an error is seen but not expected
			// or if an error is expected but when the subscring does not match the error
			failOnErrorMatch(t, err, tc.errorString)

			for k, c := range tc.mockCalls {
				if !c.called {
					t.Errorf("Expecting call with args %s", k)
				}
			}
			if len(unexpectedKeys) > 0 {
				t.Errorf("Received unexpected calls %v", unexpectedKeys)
			}
		})
	}
}

func TestEnsureElectionTimeout(t *testing.T) {
	var mockCalls map[string]*mockRes
	unexpectedKeys := make([]string, 0)
	mock := func(timeout int, args ...string) (string, string, error) {
		key := keyForArgs(args...)
		res, ok := mockCalls[key]
		if !ok {
			unexpectedKeys = append(unexpectedKeys, key)
			return "", "key not found", fmt.Errorf("key not found")
		}
		res.called = true
		return res.res, res.stderr, res.err
	}

	db := &dbProperties{
		appCtl:                mock,
		dbName:                "OVN_Northbound",
		clusterStatusRetryCnt: &nbClusterStatusRetryCnt,
	}
	tests := []struct {
		desc         string
		mockCalls    map[string]*mockRes
		timeout      int
		role         string
		currentTimer string
		errorString  string
	}{
		{
			desc: "Test error: Unable to get cluster status",
			mockCalls: map[string]*mockRes{
				keyForArgs("cluster/status", "OVN_Northbound"): {
					res:    "",
					stderr: "failure",
					err:    fmt.Errorf("failure"),
				},
			},
			errorString: "unable to get cluster status for",
		},
		{
			desc:         "Test error: Failed to get current election timer",
			mockCalls:    map[string]*mockRes{},
			currentTimer: "a",
			role:         "leader",
			errorString:  "failed to get current election timer",
		},
		{
			desc:         "Follower, not trying to change",
			mockCalls:    map[string]*mockRes{},
			timeout:      1000,
			role:         "follower",
			currentTimer: "10000",
		},
		{
			desc:         "leader, timer doesn't change",
			mockCalls:    map[string]*mockRes{},
			timeout:      1000,
			role:         "leader",
			currentTimer: "1000",
		},
		{
			desc: "Test error: failed to change election timer when leader timer must change",
			mockCalls: map[string]*mockRes{
				keyForArgs("cluster/change-election-timer", "OVN_Northbound", "2000"): {
					res:    "",
					stderr: "failure",
					err:    fmt.Errorf("failure"),
				},
			},
			timeout:      2000,
			role:         "leader",
			currentTimer: "1500",
			errorString:  "failed to change election timer for",
		},
		{
			desc: "Test error: failed to change election timer when leader timer must change but desired is more than double",
			mockCalls: map[string]*mockRes{
				keyForArgs("cluster/change-election-timer", "OVN_Northbound", "3000"): {
					res:    "",
					stderr: "failure",
					err:    fmt.Errorf("failure"),
				},
			},
			timeout:      5000,
			role:         "leader",
			currentTimer: "1500",
			errorString:  "failed to change election timer for",
		},
		{
			desc: "leader, timer must change",
			mockCalls: map[string]*mockRes{
				keyForArgs("cluster/change-election-timer", "OVN_Northbound", "2000"): {
					res:    "change of election timer initiated",
					stderr: "",
					err:    nil,
				},
			},
			timeout:      2000,
			role:         "leader",
			currentTimer: "1500",
		},
		{
			desc: "leader, timer must change but desired is more than double",
			mockCalls: map[string]*mockRes{
				keyForArgs("cluster/change-election-timer", "OVN_Northbound", "3000"): {
					res:    "change of election timer initiated",
					stderr: "",
					err:    nil,
				},
			},
			timeout:      5000,
			role:         "leader",
			currentTimer: "1500",
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			// default mockCalls which may be supplemented or overwritten by
			// more specific tc mockCalls from the above maps
			mockCalls = map[string]*mockRes{
				keyForArgs("cluster/status", "OVN_Northbound"): {
					res: fmt.Sprintf(
						status_template,
						serverAddress,
						"OVN_Northbound",
						tc.role,
						tc.currentTimer,
						servers),
					stderr: "",
					err:    nil,
				},
			}
			for k, v := range tc.mockCalls {
				mockCalls[k] = v
			}

			db.electionTimer = tc.timeout
			err := ensureElectionTimeout(db)

			// fail either if an error is seen but not expected
			// or if an error is expected but when the subscring does not match the error
			failOnErrorMatch(t, err, tc.errorString)

			for k, c := range tc.mockCalls {
				if !c.called {
					t.Errorf("Expecting call with args %s", k)
				}
			}
			if len(unexpectedKeys) > 0 {
				t.Errorf("Received unexpected calls %v", unexpectedKeys)
			}
		})
	}
}

func TestResetRaftDB(t *testing.T) {
	var mockCalls map[string]*mockRes
	unexpectedKeys := make([]string, 0)
	mock := func(timeout int, args ...string) (string, string, error) {
		key := keyForArgs(args...)
		res, ok := mockCalls[key]
		if !ok {
			unexpectedKeys = append(unexpectedKeys, key)
			return "", "key not found", fmt.Errorf("key not found")
		}
		res.called = true
		return res.res, res.stderr, res.err
	}

	db := &dbProperties{
		appCtl: mock,
	}
	tests := []struct {
		desc         string
		dbAlias      string
		dbName       string
		createDbFile bool
		mockCalls    map[string]*mockRes
		errorString  string
	}{
		{
			desc:        "Failed to back up the db to backupFile",
			dbAlias:     "ovnnb",
			dbName:      "OVN_Northbound",
			mockCalls:   map[string]*mockRes{},
			errorString: "failed to back up the db to backupFile",
		},
		{
			desc:         "Failed to restart the database",
			dbAlias:      "ovnnb",
			dbName:       "OVN_Northbound",
			createDbFile: true,
			mockCalls: map[string]*mockRes{
				keyForArgs("exit"): {
					res:    "",
					stderr: "Failed restart",
					err:    fmt.Errorf("failed restart"),
				},
			},
			errorString: "unable to restart the ovn db",
		},
		{
			desc:         "Successful database backup",
			dbAlias:      "ovnnb",
			dbName:       "OVN_Northbound",
			createDbFile: true,
			mockCalls: map[string]*mockRes{
				keyForArgs("exit"): {
					res:    "",
					stderr: "",
					err:    nil,
				},
			},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			// default mockCalls which may be supplemented or overwritten by
			// more specific tc mockCalls from the above maps
			// TBD - remove if not needed
			mockCalls = map[string]*mockRes{}
			for k, v := range tc.mockCalls {
				mockCalls[k] = v
			}

			db.dbName = tc.dbName
			db.dbAlias = tc.dbAlias

			// resetRaftDb expects a file in the current directory with the db alias'
			// name; create it
			createDbFile(t, tc.dbAlias, tc.createDbFile)
			// test resetRaftDb
			backupFileName, err := resetRaftDB(db)
			// clean up the database backup
			deleteDbFile(t, backupFileName)

			// fail either if an error is seen but not expected
			// or if an error is expected but when the subscring does not match the error
			failOnErrorMatch(t, err, tc.errorString)

			for k, c := range tc.mockCalls {
				if !c.called {
					t.Errorf("Expecting call with args %s", k)
				}
			}
			if len(unexpectedKeys) > 0 {
				t.Errorf("Received unexpected calls %v", unexpectedKeys)
			}
		})
	}
}

func keyForArgs(args ...string) string {
	return strings.Join(args, "-")
}

// create file with name, fail on error or if the file already exists
func createDbFile(t *testing.T, name string, create bool) {
	if !create {
		return
	}
	_, err := os.Stat(name)
	if os.IsNotExist(err) {
		f, err := os.OpenFile(name, os.O_RDONLY|os.O_CREATE, 0644)
		if err != nil {
			t.Errorf("Unexpected errror: %v", err)
		}
		f.Close()
	} else {
		t.Errorf("File already exists: %s, %v", name, err)
	}
}

// delete file at location, fail on delete error
func deleteDbFile(t *testing.T, name string) {
	if name == "" {
		return
	}
	err := os.Remove(name)
	if err != nil {
		t.Errorf(err.Error())
	}
}

// fail either if an error is seen but not expected
// or if an error is expected but when the subscring does not match the error
func failOnErrorMatch(t *testing.T, err error, errorString string) {
	if err != nil {
		if errorString == "" || !strings.Contains(err.Error(), errorString) {
			t.Errorf("Unexpected outcome. Got error '%v' but it does not contain expected string '%s'", err, errorString)
		}
	} else {
		if errorString != "" {
			t.Errorf("No error expected. However, received '%v'", err)
		}
	}
}

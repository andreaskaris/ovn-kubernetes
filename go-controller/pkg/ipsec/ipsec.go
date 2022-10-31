package ipsec

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/klog/v2"
	"k8s.io/utils/exec"
)

const (
	tunnelRegex = `^conn ([^%\s]\S*)`
	ipsecBin    = `/usr/sbin/ipsec`
)

// MonitorTunnels continuously checks IPsec tunnel status.
// If a valid node name is provided then taint the node with the given name.
func MonitorTunnels(configFile string, probe corev1.Probe, nodeName string) error {
	var consecutiveFailures int32
	var consecutiveSuccess int32
	probeByte, err := json.Marshal(probe)
	if err != nil {
		return err
	}

	time.Sleep(time.Duration(probe.InitialDelaySeconds) * time.Second)
	for true {
		err := CheckTunnels(configFile)
		if err != nil {
			klog.V(5).Infof("Single probe failed, probe configuration: %s, err: %v",
				probeByte, err)
			consecutiveFailures++
			consecutiveSuccess = 0
		} else {
			klog.V(5).Infof("Single probe succeeded, probe configuration: %s, err: %v",
				probeByte, err)
			consecutiveSuccess++
			consecutiveFailures = 0
		}
		if consecutiveFailures >= probe.FailureThreshold {
			klog.Warning(fmt.Errorf("Monitoring IPsec tunnels failed for probe: %s, err: %v",
				probeByte, err))
			if err := taintNode(nodeName, true); err != nil {
				return err
			}
		}
		if consecutiveSuccess >= probe.SuccessThreshold {
			klog.Info(fmt.Errorf("Monitoring IPsec tunnels succeeded for probe: %s, err: %v",
				probeByte, err))
			if err := taintNode(nodeName, false); err != nil {
				return err
			}
		}
		time.Sleep(time.Duration(probe.PeriodSeconds) * time.Second)
	}
	return nil
}

// taintNode will attempt to taint the given node if addTaint is true.
// Otherwise, it will attempt to remove the given taint.
func taintNode(nodeName string, addTaint bool) error {
	if nodeName == "" {
		return nil
	}

	if addTaint {
		klog.Infof("Tainting node %s", nodeName)
	} else {
		klog.Infof("Removing node taint for %s", nodeName)
	}
	return nil
}

// CheckTunnels parses all tunnels from configFile and makes sure that they are up.
// If any of the tunnels are not up, it will return an error.
func CheckTunnels(configFile string) error {
	tunnels, err := getTunnels(configFile)
	if err != nil {
		return err
	}
	tunnelTrafficStatus, err := readTunnelTrafficStatus()
	if err != nil {
		return err
	}
	var errs []error
	for _, tun := range tunnels {
		if _, ok := tunnelTrafficStatus[tun]; !ok {
			errs = append(errs, fmt.Errorf("tunnel %s not established", tun))
		}
	}
	return kerrors.NewAggregate(errs)
}

// getTunnels will parse configFile for tunnel names that match tunnelRegex. It returns a
// slice of configured tunnel names.
func getTunnels(configFile string) ([]string, error) {
	f, err := os.Open(configFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var tunnels []string
	re := regexp.MustCompile(tunnelRegex)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		t := re.FindStringSubmatch(line)
		if t != nil && len(t) > 1 {
			tunnels = append(tunnels, string(t[1]))
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return tunnels, nil
}

// readTunnelTrafficStatus runs the ipsec command to get the tunnel status, parses the output and
// returns a map that shows the status for each of the tunnels.
func readTunnelTrafficStatus() (map[string]string, error) {
	var errs []error
	tunnels := make(map[string]string)

	//	tunnelStatus := make(map[string]string)
	cmd := exec.New().Command(ipsecBin, "trafficstatus")
	buff := &bytes.Buffer{}
	cmd.SetStdout(buff)
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(buff)
	for scanner.Scan() {
		line := scanner.Text()
		sLine := strings.Split(line, ":")
		if len(sLine) != 2 {
			errs = append(errs, fmt.Errorf("invalid line: %s", line))
			continue
		}
		connInfo := strings.Split(sLine[1], ",")
		if len(connInfo) < 2 {
			errs = append(errs, fmt.Errorf("invalid line: %s", line))
			continue
		}
		tunnelName := strings.Trim(connInfo[0], `" `)
		tunnels[tunnelName] = sLine[1]
	}
	return tunnels, kerrors.NewAggregate(errs)
}

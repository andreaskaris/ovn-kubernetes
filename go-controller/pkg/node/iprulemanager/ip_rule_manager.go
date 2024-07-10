package iprulemanager

import (
	"fmt"
	"sync"
	"time"

	"k8s.io/klog/v2"

	"github.com/vishvananda/netlink"

	utilerrors "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util/errors"
)

type ipRule struct {
	rule   *netlink.Rule
	delete bool
}

type Controller struct {
	mu    *sync.Mutex
	rules []ipRule
	// only explicit IP rules (via fn Add) are allowed when a priority is owned. Other IP rules will be removed.
	ownPriorities map[int]bool
	v4            bool
	v6            bool
}

// NewController creates a new linux IP rule manager
func NewController(v4, v6 bool) *Controller {
	nc := &Controller{
		mu:            &sync.Mutex{},
		rules:         make([]ipRule, 0),
		ownPriorities: make(map[int]bool, 0),
		v4:            v4,
		v6:            v6,
	}
	if err := nc.loadHostRules(); err != nil {
		klog.Warningf("Could not load ip rules from host, err: %q", err)
	}
	return nc
}

// Run starts manages linux IP rules
func (rm *Controller) Run(stopCh <-chan struct{}, syncPeriod time.Duration) {
	var err error
	ticker := time.NewTicker(syncPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			rm.mu.Lock()
			if err = rm.reconcile(); err != nil {
				klog.Errorf("IP Rule manager: failed to reconcile (retry in %s): %v", syncPeriod.String(), err)
			}
			rm.mu.Unlock()
		}
	}
}

// Add ensures an IP rule is applied even if it is altered by something else, it will be restored
func (rm *Controller) Add(rule netlink.Rule) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	// rm.add == false -> rule was not added -> return from Add().
	if !rm.add(rule) {
		return nil
	}
	// rm.add == true -> rule was added -> trigger reconcilitation.
	return rm.reconcile()
}

// Delete stops managed an IP rule and ensures its deleted
func (rm *Controller) Delete(rule netlink.Rule) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	var reconcileNeeded bool
	for i, r := range rm.rules {
		if areNetlinkRulesEqual(r.rule, &rule) {
			rm.rules[i].delete = true
			reconcileNeeded = true
			break
		}
	}
	if reconcileNeeded {
		return rm.reconcile()
	}
	return nil
}

// OwnPriority ensures any IP rules observed with priority 'priority' must be specified otherwise its removed
func (rm *Controller) OwnPriority(priority int) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.ownPriorities[priority] = true
	return rm.reconcile()
}

func (rm *Controller) reconcile() error {
	start := time.Now()
	defer func() {
		klog.V(5).Infof("Reconciling IP rules took %v", time.Since(start))
	}()

	rulesFound, err := rm.getNetlinkRules()
	if err != nil {
		return err
	}
	var errors []error
	rulesToKeep := make([]ipRule, 0)
	for _, r := range rm.rules {
		// delete IP rule by first checking if it exists and if so, delete it
		if r.delete {
			if found, foundRoute := isNetlinkRuleInSlice(rulesFound, r.rule); found {
				if err = netlink.RuleDel(foundRoute); err != nil {
					// retry later
					rulesToKeep = append(rulesToKeep, r)
					errors = append(errors, err)
				}
			}
		} else {
			// add IP rule by first checking if it exists and if not, add it
			rulesToKeep = append(rulesToKeep, r)
			if found, _ := isNetlinkRuleInSlice(rulesFound, r.rule); !found {
				if err = netlink.RuleAdd(r.rule); err != nil {
					errors = append(errors, err)
				}
			}
		}
	}

	var found bool
	for priority := range rm.ownPriorities {
		for _, ruleFound := range rulesFound {
			if ruleFound.Priority != priority {
				continue
			}
			found = false
			for _, ruleWanted := range rm.rules {
				if ruleWanted.rule.Priority != priority {
					continue
				}
				if areNetlinkRulesEqual(ruleWanted.rule, &ruleFound) {
					found = true
					break
				}
			}
			if !found {
				klog.Infof("Rule manager: deleting stale IP rule (%s) found at priority %d", ruleFound.String(), priority)
				if err = netlink.RuleDel(&ruleFound); err != nil {
					errors = append(errors, fmt.Errorf("failed to delete stale IP rule (%s) found at priority %d: %v",
						ruleFound.String(), priority, err))
				}
			}
		}
	}

	rm.rules = rulesToKeep
	return utilerrors.Join(errors...)
}

// areNetlinkRulesEqual returns true if the provided rules are equal (they have the same IP address family and their
// string representations are equal).
func areNetlinkRulesEqual(r1, r2 *netlink.Rule) bool {
	return r1.Family == r2.Family && r1.String() == r2.String()
}

func isNetlinkRuleInSlice(rules []netlink.Rule, candidate *netlink.Rule) (bool, *netlink.Rule) {
	for _, r := range rules {
		r := r
		if r.Priority != candidate.Priority {
			continue
		}
		if areNetlinkRulesEqual(&r, candidate) {
			return true, &r
		}
	}
	return false, netlink.NewRule()
}

// add adds an IP rule to the in memory list of rules. Returns true if the rule was appended,
// false if the rule was not added because it already exists.
func (rm *Controller) add(rule netlink.Rule) bool {
	// check if we are already managing this route and if so, no-op
	for _, existingRule := range rm.rules {
		if areNetlinkRulesEqual(existingRule.rule, &rule) {
			return false
		}
	}
	rm.rules = append(rm.rules, ipRule{rule: &rule})
	return true
}

// getNetlinkRules retrieves all ip rules via netlink for this manager's IP address families.
func (rm *Controller) getNetlinkRules() ([]netlink.Rule, error) {
	var family int
	if rm.v4 && rm.v6 {
		family = netlink.FAMILY_ALL
	} else if rm.v4 {
		family = netlink.FAMILY_V4
	} else if rm.v6 {
		family = netlink.FAMILY_V6
	}

	return netlink.RuleList(family)
}

// loadHostRules retrieves all ip rules via netlink for this manager's IP address families and adds them to the in
// memory list of rules.
func (rm *Controller) loadHostRules() error {
	rules, err := rm.getNetlinkRules()
	if err != nil {
		return err
	}

	rm.mu.Lock()
	defer rm.mu.Unlock()
	for _, rule := range rules {
		_ = rm.add(rule)
	}
	return nil
}

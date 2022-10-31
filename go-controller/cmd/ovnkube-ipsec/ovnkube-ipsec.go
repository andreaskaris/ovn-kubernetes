package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ipsec"
	"github.com/urfave/cli/v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
)

func main() {
	c := cli.NewApp()
	c.Name = "ovnkube-ipsec"
	c.Usage = "IPsec utils for kubernetes ovn"
	c.Version = config.Version
	c.Flags = []cli.Flag{
		&cli.IntFlag{
			Name: "loglevel",
			Usage: "klog verbosity level (default: 4). Info, warn, fatal, error are always printed. " +
				"For debug messages, use 5. ",
			Value: 0,
		},
	}
	c.Commands = []*cli.Command{
		&checkIPsecTunnels,
		&monitorIPsecTunnels,
	}
	c.Before = func(ctx *cli.Context) error {
		var level klog.Level

		klog.SetOutput(os.Stderr)
		if err := level.Set(strconv.Itoa(ctx.Int("loglevel"))); err != nil {
			return fmt.Errorf("failed to set klog log level %v", err)
		}
		return nil
	}
	if err := c.Run(os.Args); err != nil {
		klog.Exit(err)
	}
}

// checkIPsecTunnels checks if all configured IPsec tunnels are up.
var checkIPsecTunnels = cli.Command{
	Name:  "check-tunnels",
	Usage: "Check all IPsec tunnels",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "config",
			Usage: "Location of the ipsec config file",
			Value: "/etc/ipsec.conf",
		},
	},
	Action: func(context *cli.Context) error {
		configFileFlag := context.Value("config")
		configFile, ok := configFileFlag.(string)
		if !ok {
			return fmt.Errorf("Could not parse config flag")
		}
		return ipsec.CheckTunnels(configFile)
	},
}

// monitorIPsecTunnels continuously monitors all IPsec tunnels and taints the node
// on failure.
var monitorIPsecTunnels = cli.Command{
	Name:  "monitor-tunnels",
	Usage: "Monitor all IPsec tunnels and taint node on failure",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "config",
			Usage: "Location of the ipsec config file",
			Value: "/etc/ipsec.conf",
		},
		&cli.IntFlag{
			Name:  "initial-delay-seconds",
			Usage: "Length of time before health checking is activated",
			Value: 0,
		},
		&cli.IntFlag{
			Name:  "period-seconds",
			Usage: "How often (in seconds) to perform the probe",
			Value: 60,
		},
		&cli.IntFlag{
			Name:  "success-threshold",
			Usage: "Minimum consecutive successes for the probe to be considered successful after having failed",
			Value: 3,
		},
		&cli.IntFlag{
			Name:  "failure-threshold",
			Usage: "Minimum consecutive failures for the probe to be considered failed after having succeeded",
			Value: 3,
		},
		&cli.StringFlag{
			Name:  "taint-node",
			Usage: "Taint the node that matches this node name, do not attempt to taint if empty",
			Value: "",
		},
	},
	Action: func(context *cli.Context) error {
		configFileFlag := context.Value("config")
		configFile, ok := configFileFlag.(string)
		if !ok {
			return fmt.Errorf("could not parse config flag")
		}
		initialDelaySecondsFlag := context.Value("initial-delay-seconds")
		initialDelaySeconds, ok := initialDelaySecondsFlag.(int)
		if !ok {
			return fmt.Errorf("could not parse initial-delay-seconds flag")
		}
		periodSecondsFlag := context.Value("period-seconds")
		periodSeconds, ok := periodSecondsFlag.(int)
		if !ok {
			return fmt.Errorf("could not parse period-seconds flag")
		}
		successThresholdFlag := context.Value("success-threshold")
		successThreshold, ok := successThresholdFlag.(int)
		if !ok {
			return fmt.Errorf("could not parse success-threshold flag")
		}
		failureThresholdFlag := context.Value("failure-threshold")
		failureThreshold, ok := failureThresholdFlag.(int)
		if !ok {
			return fmt.Errorf("could not parse failure-threshold flag")
		}
		taintNodeFlag := context.Value("taint-node")
		taintNode, ok := taintNodeFlag.(string)
		if !ok {
			return fmt.Errorf("could not parse node-name flag")
		}
		return ipsec.MonitorTunnels(
			configFile,
			corev1.Probe{
				InitialDelaySeconds: int32(initialDelaySeconds),
				PeriodSeconds:       int32(periodSeconds),
				SuccessThreshold:    int32(successThreshold),
				FailureThreshold:    int32(failureThreshold),
			},
			taintNode,
		)
	},
}

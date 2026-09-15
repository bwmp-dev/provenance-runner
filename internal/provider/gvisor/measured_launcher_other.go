//go:build !linux

package gvisor

import "io"

const MeasuredLauncherCommand = "__gvisor-measured-launch"
const MeasuredChildCommand = "__gvisor-measured-child"
const MeasuredNetworkChildCommand = "__gvisor-measured-network-child"
const RouterChildCommand = "__provenance-router-holder"

func RunMeasuredLauncher([]string, io.Writer) int     { return runscFailureExitCode }
func RunMeasuredChild([]string, io.Writer) int        { return runscFailureExitCode }
func RunMeasuredNetworkChild([]string, io.Writer) int { return runscFailureExitCode }
func RunRouterChild([]string, io.Writer) int          { return runscFailureExitCode }

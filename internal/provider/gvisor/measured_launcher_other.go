//go:build !linux

package gvisor

import "io"

const MeasuredLauncherCommand = "__gvisor-measured-launch"
const MeasuredChildCommand = "__gvisor-measured-child"

func RunMeasuredLauncher([]string, io.Writer) int { return runscFailureExitCode }
func RunMeasuredChild([]string, io.Writer) int    { return runscFailureExitCode }

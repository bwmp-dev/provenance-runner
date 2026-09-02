//go:build !linux

package gvisor

// Resource measurements are obtained from Linux cgroup v2 files. Other
// operating systems keep the provider compile-safe but report no fabricated
// counters; hosted execution remains Linux-only.
func (e *preparedEnvironment) sampleUsageUntil(stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	<-stop
}

func (e *preparedEnvironment) sampleUsage() {}

func readOuterPIDDenials(string) (uint64, bool) { return 0, false }

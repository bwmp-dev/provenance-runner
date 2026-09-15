//go:build linux

package networkpolicy

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestChildLivenessInterruptedObservation(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		interruptions, count int
		events               int16
		err                  error
	}{
		{"living", 0, 0, 0, nil},
		{"interrupted-living", 2, 0, 0, nil},
		{"interrupted-exited", 2, 1, unix.POLLIN, nil},
		{"interrupted-invalid", 2, 1, unix.POLLNVAL, nil},
		{"other-error", 0, 0, 0, unix.EBADF},
		{"signal-flood", 8, 0, 0, unix.EINTR},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fds := []unix.PollFd{{Fd: 17, Events: unix.POLLIN}}
			calls := 0
			n, err := pollChildLiveness(fds, func(got []unix.PollFd, timeout int) (int, error) {
				if timeout != 0 || len(got) != 1 || got[0].Fd != 17 || got[0].Events != unix.POLLIN || got[0].Revents != 0 {
					t.Fatal("observation identity, bound or event reset changed")
				}
				calls++
				if calls <= tc.interruptions {
					got[0].Revents = unix.POLLERR
					return -1, unix.EINTR
				}
				got[0].Revents = tc.events
				return tc.count, tc.err
			})
			wantCalls := tc.interruptions + 1
			if wantCalls > 8 {
				wantCalls = 8
			}
			if n != tc.count || err != tc.err || calls != wantCalls {
				t.Fatalf("result %d %v after %d observations", n, err, calls)
			}
			if err == nil && fds[0].Revents != tc.events {
				t.Fatal("kernel exit events lost")
			}
		})
	}
}

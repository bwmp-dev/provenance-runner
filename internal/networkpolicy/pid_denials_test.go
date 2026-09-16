package networkpolicy

import "testing"

func TestPIDDenialsClosedScalar(t *testing.T) {
	for _, test := range []struct {
		raw  string
		want uint64
	}{{"max 0\n", 0}, {"max 19\n", 19}, {"max 18446744073709551615\n", ^uint64(0)}} {
		if got, err := parsePIDDenials(test.raw); err != nil || got != test.want {
			t.Fatal("valid kernel scalar", got, err)
		}
	}
	for _, raw := range []string{"", "max 1", "max -1\n", "max +1\n", "max 01\n", "max 1\nmax 1\n", "max 1\nextra 0\n", "max 18446744073709551616\n", "max 1\r\n", "max  1\n"} {
		if _, err := parsePIDDenials(raw); err == nil {
			t.Fatal("ambiguous PID count", raw)
		}
	}
}

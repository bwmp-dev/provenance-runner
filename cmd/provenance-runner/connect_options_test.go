package main

import "testing"

func TestConnectV2OptInIsExplicitAndClosed(t *testing.T) {
	for _, tc := range []struct {
		args                 []string
		uploads, v2, invalid bool
	}{
		{nil, false, false, false},
		{[]string{"--disable-object-upload-identity"}, true, false, false},
		{[]string{"--enable-terminal-evidence-v2"}, false, true, false},
		{[]string{"--enable-terminal-evidence-v2", "--disable-object-upload-identity"}, true, true, false},
		{[]string{"--disable-object-upload-identity", "--enable-terminal-evidence-v2"}, true, true, false},
		{[]string{"--enable-terminal-evidence-v2", "--enable-terminal-evidence-v2"}, false, false, true},
		{[]string{"--disable-object-upload-identity", "--disable-object-upload-identity"}, false, false, true},
		{[]string{"--enable-terminal-evidence-v3"}, false, false, true},
		{[]string{"--enable-terminal-evidence-v2=true"}, false, false, true},
		{[]string{"extra"}, false, false, true},
	} {
		u, v, err := parseConnectOptions(tc.args)
		if u != tc.uploads || v != tc.v2 || (err != nil) != tc.invalid {
			t.Fatalf("options %v mismatch", tc.args)
		}
	}
}

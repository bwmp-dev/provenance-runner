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
		u, v, secrets, err := parseConnectOptions(tc.args)
		if u != tc.uploads || v != tc.v2 || secrets || (err != nil) != tc.invalid {
			t.Fatalf("options %v mismatch", tc.args)
		}
	}
}

func TestConnectTestSecretsRequiresExactOperatorOptIn(t *testing.T) {
	for _, tc := range []struct {
		args        []string
		uploads, v2 bool
	}{
		{[]string{"--enable-test-secrets"}, false, false},
		{[]string{"--enable-test-secrets", "--enable-terminal-evidence-v2"}, false, true},
		{[]string{"--disable-object-upload-identity", "--enable-test-secrets"}, true, false},
		{[]string{"--enable-terminal-evidence-v2", "--enable-test-secrets", "--disable-object-upload-identity"}, true, true},
	} {
		u, v, secrets, err := parseConnectOptions(tc.args)
		if err != nil || u != tc.uploads || v != tc.v2 || !secrets {
			t.Fatalf("explicit operator options %v refused", tc.args)
		}
	}
	for _, args := range [][]string{
		{"--enable-test-secrets", "--enable-test-secrets"},
		{"--enable-test-secrets=true"},
		{"--enable-test-secrets=false"},
		{"--enable-test-secrets", "true"},
		{"--enable-test-secrets", "--enable-terminal-evidence-v2", "--enable-terminal-evidence-v2"},
	} {
		u, v, secrets, err := parseConnectOptions(args)
		if err == nil || u || v || secrets {
			t.Fatalf("invalid or duplicate operator options %v accepted", args)
		}
	}
}

package pluginname

import "testing"

func TestValidPaper(t *testing.T) {
	for value, valid := range map[string]bool{
		"Plugin": true, "plugin.name-1": true, "_plugin": false, ".plugin": false, "-plugin": false,
		"plugin name": false, "Paper": false, "": false,
	} {
		if got := ValidPaper(value); got != valid {
			t.Fatalf("ValidPaper(%q) = %t, want %t", value, got, valid)
		}
	}
}

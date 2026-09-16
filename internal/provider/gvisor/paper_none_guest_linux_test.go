//go:build linux

package gvisor

import (
	"fmt"
	"net"
	"os"
	"time"
)

// Controlled synthetic Java stand-in; never interprets JAR content.
func runPaperNoneFixtureGuest() int {
	if os.Getuid() != 65532 || os.Getgid() != 65532 {
		return 125
	}
	if connection, err := net.DialTimeout("tcp", "93.184.216.34:443", 100*time.Millisecond); err == nil {
		connection.Close()
		return 125
	}
	if value, err := os.ReadFile("/run/provenance/test-secrets/license"); err == nil {
		if string(value) != "synthetic-none-v2-secret" {
			return 125
		}
		fmt.Println(string(value))
		clear(value)
		fmt.Println("NONE_V2_SECRET_OK")
	} else if !os.IsNotExist(err) {
		return 125
	}
	events := []struct{ kind, data string }{
		{"TEST_PLAN", `{"status":"LOADED","consoleTests":0,"maximumCommandOutputBytes":4096}`},
		{"PROBE_LOADED", `{}`}, {"SERVER_LOADED", `{}`}, {"STABILIZATION_STARTED", `{}`},
		{"TARGET_REQUIREMENT", `{"role":"TARGET","name":"NoneFixture","configured":true,"loaded":true,"enabled":true}`},
		{"STABILIZATION_COMPLETED", `{}`}, {"SERVER_READY", `{"requirementsSatisfied":true}`},
		{"CLEAN_SHUTDOWN_REQUESTED", `{}`}, {"SERVER_STOPPED", `{"shutdownRequested":true}`},
	}
	file, err := os.OpenFile("/tmp/provenance-probe-events.ndjson", os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return 125
	}
	for _, event := range events {
		if _, err := fmt.Fprintf(file, "{\"timestamp\":\"2026-09-16T00:00:00Z\",\"type\":%q,\"data\":%s}\n", event.kind, event.data); err != nil {
			file.Close()
			return 125
		}
	}
	if file.Close() != nil {
		return 125
	}
	fmt.Println("NONE_V2_OK")
	return 0
}

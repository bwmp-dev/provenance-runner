//go:build linux

package measuredclient

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	cc "github.com/bwmp-dev/provenance-runner/internal/controlchannel"
)

func TestHostedMeasuredSystemdReadiness(t *testing.T) {
	if os.Getenv("PROVENANCE_DISPOSABLE_HOSTED_DAEMON") != "1" {
		t.Skip("explicit disposable hosted daemon required")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil || os.Getuid() != 994 || os.Getgid() != 981 {
		t.Fatal("dedicated disposable worker identity required")
	}
	dial := func() *cc.Channel {
		connection, err := net.DialTimeout("unixpacket", "/run/provenance-measured/socket/control.sock", time.Second)
		if err != nil {
			t.Fatal("root socket unavailable")
		}
		channel, err := cc.New(connection.(*net.UnixConn), 0)
		if err != nil {
			connection.Close()
			t.Fatal("root peer refused")
		}
		return channel
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := CheckIdle(ctx, dial()); err != nil {
		t.Fatal("root idle capability refused")
	}
	if err := CheckSecrets(ctx, dial()); err != nil {
		t.Fatal("root secret capability refused")
	}
	maximum, err := ReadMaximum(ctx, dial())
	if err != nil || maximum.GetResources().GetCpuMillis() != 1000 || maximum.GetResources().GetMemoryBytes() != 128<<20 || maximum.GetResources().GetProcessCount() != 64 {
		t.Fatal("root policy differs from fixture provisioning")
	}
}

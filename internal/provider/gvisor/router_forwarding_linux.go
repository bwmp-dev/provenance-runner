//go:build linux

package gvisor

import (
	"io"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// Only called by the closed router child after its mapping, inherited handles,
// and separation from the parent's network namespace have been verified.
// No caller-selected path or value is accepted, and no links exist yet.
func prepareRouterForwarding() bool {
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		return false
	}
	for _, setting := range []struct{ path, value string }{
		{"/proc/sys/net/ipv4/ip_forward", "1\n"},
		{"/proc/sys/net/ipv6/conf/all/forwarding", "1\n"},
		{"/proc/sys/net/ipv6/conf/default/forwarding", "1\n"},
		{"/proc/sys/net/ipv4/conf/all/send_redirects", "0\n"},
		{"/proc/sys/net/ipv4/conf/default/send_redirects", "0\n"},
		{"/proc/sys/net/ipv6/conf/all/accept_ra", "0\n"},
		{"/proc/sys/net/ipv6/conf/default/accept_ra", "0\n"},
	} {
		file, err := os.OpenFile(setting.path, unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return false
		}
		var fs unix.Statfs_t
		if unix.Fstatfs(int(file.Fd()), &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC {
			file.Close()
			return false
		}
		n, err := file.WriteString(setting.value)
		closed := file.Close()
		if err != nil || n != len(setting.value) || closed != nil {
			return false
		}
		file, err = os.OpenFile(setting.path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return false
		}
		valid := unix.Fstatfs(int(file.Fd()), &fs) == nil && fs.Type == unix.PROC_SUPER_MAGIC
		raw, err := io.ReadAll(io.LimitReader(file, 3))
		closed = file.Close()
		if !valid || err != nil || closed != nil || string(raw) != setting.value {
			return false
		}
	}
	return true
}

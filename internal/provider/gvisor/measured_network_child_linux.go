//go:build linux

package gvisor

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const MeasuredNetworkChildCommand = "__gvisor-measured-network-child"

var measuredNetworkJobID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

// RunMeasuredNetworkChild is a closed handoff, not a privileged service API.
// The trusted owning controller must create and retain this direct mapped child,
// place it in the exact aggregate resource boundary, and install current routed
// protection before releasing its launch barrier. No production provider calls
// this command yet; network admission/measurement fences remain unchanged.
//
// Args are exactly job/UID/GID/overflow-UID/overflow-GID/private-root/image-SHA/mode.
// FDs 3..7 match the retained measured-root handoff; 8 and 9 are the controller's
// network and mount namespaces, used only to refuse inherited ambient execution.
// FD 10 is a read-only launch pipe: the controller writes exactly 's' and closes
// it only after ownership, aggregate limits and current route enforcement pass.
// FD 11 is a separate write-only readiness pipe. The initialized child writes
// exactly 'r' then closes it before waiting for launch. Readiness is not authority.
func RunMeasuredNetworkChild(arguments []string, stderr io.Writer) int {
	inputs, run, ok := measuredNetworkInputs(arguments)
	if !ok {
		fmt.Fprintln(stderr, "measured network handoff refused: inputs")
		return runscFailureExitCode
	}
	values := [4]uint32{}
	for i := range values {
		n, _ := strconv.ParseUint(arguments[i+1], 10, 32)
		values[i] = uint32(n)
	}
	mapped := func() bool {
		if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
			return false
		}
		groups, err := os.Getgroups()
		if err != nil || len(groups) != 0 {
			return false
		}
		for _, item := range []struct {
			path           string
			root, overflow uint32
		}{{"/proc/self/uid_map", values[0], values[2]}, {"/proc/self/gid_map", values[1], values[3]}} {
			raw, err := os.ReadFile(item.path)
			if err != nil || !exactNetworkMapping(raw, item.root, item.overflow) {
				return false
			}
		}
		for _, item := range []struct {
			fd   int
			kind int
			path string
		}{{8, unix.CLONE_NEWNET, "/proc/self/ns/net"}, {9, unix.CLONE_NEWNS, "/proc/self/ns/mnt"}} {
			kind, err := unix.IoctlRetInt(item.fd, unix.NS_GET_NSTYPE)
			if err != nil || kind != item.kind {
				return false
			}
			var current, parent unix.Stat_t
			if unix.Fstat(item.fd, &parent) != nil || unix.Stat(item.path, &current) != nil || (parent.Dev == current.Dev && parent.Ino == current.Ino) {
				return false
			}
		}
		// Namespace references never reach runsc/gofer/the guest.
		unix.CloseOnExec(8)
		unix.CloseOnExec(9)
		flags, err := unix.FcntlInt(10, unix.F_GETFL, 0)
		var gateStat unix.Stat_t
		if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY || unix.Fstat(10, &gateStat) != nil || gateStat.Mode&unix.S_IFMT != unix.S_IFIFO || unix.SetNonblock(10, true) != nil {
			return false
		}
		gate := os.NewFile(10, "measured-network-launch-gate")
		defer gate.Close()
		readyFlags, err := unix.FcntlInt(11, unix.F_GETFL, 0)
		var readyStat unix.Stat_t
		if err != nil || readyFlags&unix.O_ACCMODE != unix.O_WRONLY || unix.Fstat(11, &readyStat) != nil || readyStat.Mode&unix.S_IFMT != unix.S_IFIFO || unix.SetNonblock(11, true) != nil {
			return false
		}
		ready := os.NewFile(11, "measured-network-child-ready")
		defer ready.Close()
		if ready.SetWriteDeadline(time.Now().Add(5*time.Second)) != nil {
			return false
		}
		if n, err := ready.Write([]byte{'r'}); err != nil || n != 1 || ready.Close() != nil {
			return false
		}
		return awaitMeasuredNetworkGate(gate, time.Now().Add(30*time.Second))
	}
	return runMeasuredChild(inputs, stderr, mapped, func(value []string) bool {
		return os.Getenv("GVISOR_SIDECAR_BINARIES_DIR") == "" && os.Getenv("GVISOR_ENFORCE_RELEASE") == "" && slices.Equal(value, run)
	})
}

func awaitMeasuredNetworkGate(gate *os.File, deadline time.Time) bool {
	return awaitMeasuredNetworkToken(gate, deadline, 's')
}

func awaitMeasuredNetworkToken(gate *os.File, deadline time.Time, expected byte) bool {
	if gate == nil {
		return false
	}
	stat, err := gate.Stat()
	if err != nil || stat.Mode()&os.ModeNamedPipe == 0 || gate.SetReadDeadline(deadline) != nil {
		return false
	}
	var token [1]byte
	if _, err := io.ReadFull(gate, token[:]); err != nil || token[0] != expected {
		return false
	}
	n, err := gate.Read(token[:])
	return n == 0 && err == io.EOF
}

func measuredNetworkInputs(arguments []string) ([]string, []string, bool) {
	if len(arguments) != 8 || !measuredNetworkJobID.MatchString(arguments[0]) || arguments[0] == "00000000-0000-0000-0000-000000000000" || arguments[7] != "embedded-executable" {
		return nil, nil, false
	}
	ids := [4]uint64{}
	for i := range ids {
		n, err := strconv.ParseUint(arguments[i+1], 10, 32)
		if err != nil || n == 0 || n == 1<<32-1 || strconv.FormatUint(n, 10) != arguments[i+1] {
			return nil, nil, false
		}
		ids[i] = n
	}
	if ids[0] == ids[2] || ids[1] == ids[3] {
		return nil, nil, false
	}
	root := arguments[5]
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || filepath.Base(root) != ".measured-root" || filepath.Base(filepath.Dir(root)) != arguments[0] || len(root) > 4096 || strings.ContainsAny(root, "\x00\r\n") {
		return nil, nil, false
	}
	if len(arguments[6]) != 64 || strings.Trim(arguments[6], "0123456789abcdef") != "" {
		return nil, nil, false
	}
	bundle := filepath.Dir(root)
	run := []string{"--root=" + filepath.Join(bundle, ".runsc-state"), "--rootless=false", "--network=sandbox", "--platform=systrap", "--overlay2=none", "--directfs=false", "--file-access=exclusive", "--file-access-mounts=exclusive", "--gofer-network-namespace=new", "--net-raw=false", "--host-uds=none", "--host-fifo=none", "--allow-suid=false", "--character-device-policy=emulated-only", "--ignore-cgroups=true", "run", "--bundle=" + bundle, arguments[0]}
	inputs := append([]string{root, arguments[6], arguments[7], "--"}, run...)
	return inputs, run, true
}

func exactNetworkMapping(raw []byte, root, overflow uint32) bool {
	if len(raw) > 4096 || root == 0 || overflow == 0 || root == overflow || root == ^uint32(0) || overflow == ^uint32(0) {
		return false
	}
	fields := strings.Fields(string(raw))
	want := []string{"0", strconv.FormatUint(uint64(root), 10), "1", "65534", strconv.FormatUint(uint64(overflow), 10), "1"}
	return slices.Equal(fields, want)
}

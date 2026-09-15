//go:build linux

package gvisor

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const RouterChildCommand = "__provenance-router-holder"

func routerChildInputs(args []string) ([4]uint32, bool) {
	var ids [4]uint32
	if len(args) != 5 || !measuredNetworkJobID.MatchString(args[0]) || args[0] == "00000000-0000-0000-0000-000000000000" {
		return ids, false
	}
	for i := range ids {
		n, err := strconv.ParseUint(args[i+1], 10, 32)
		if err != nil || n == 0 || n == 1<<32-1 || strconv.FormatUint(n, 10) != args[i+1] {
			return ids, false
		}
		ids[i] = uint32(n)
	}
	return ids, ids[0] != ids[2] && ids[1] != ids[3]
}

// RunRouterChild is a closed, credential-free namespace holder. It executes no
// command and reads no job payload. Before dropping privileges, it configures
// only fixed forwarding controls in its fresh private namespace. FD3 is its lifetime
// pipe, FD4 readiness, FD5 the retained runner, FD6 the parent's network namespace.
func RunRouterChild(args []string, stderr io.Writer) int {
	fail := func() int { fmt.Fprintln(stderr, "router holder refused"); return runscFailureExitCode }
	ids, ok := routerChildInputs(args)
	if !ok || os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return fail()
	}
	groups, err := os.Getgroups()
	if err != nil || len(groups) != 0 {
		return fail()
	}
	for i, path := range []string{"/proc/self/uid_map", "/proc/self/gid_map"} {
		raw, err := os.ReadFile(path)
		if err != nil || !exactNetworkMapping(raw, ids[i], ids[i+2]) {
			return fail()
		}
	}
	var parent, current unix.Stat_t
	kind, err := unix.IoctlRetInt(6, unix.NS_GET_NSTYPE)
	if err != nil || kind != unix.CLONE_NEWNET || unix.Fstat(6, &parent) != nil || unix.Stat("/proc/self/ns/net", &current) != nil || (parent.Dev == current.Dev && parent.Ino == current.Ino) {
		return fail()
	}
	for fd, mode := range map[int]int{3: unix.O_RDONLY, 4: unix.O_WRONLY} {
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
		var st unix.Stat_t
		if err != nil || flags&unix.O_ACCMODE != mode || unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFIFO || unix.SetNonblock(fd, true) != nil {
			return fail()
		}
	}
	if !prepareRouterForwarding() {
		return fail()
	}
	// The holder needs no capabilities after private setup and never execs.
	// Capabilities and no-new-privileges are per-thread. Go has already created
	// runtime threads, so changing only the calling thread is insufficient.
	if _, _, err := syscall.AllThreadsSyscall6(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0); err != 0 {
		return fail()
	}
	for capability := 0; capability < 64; capability++ {
		if _, _, err := syscall.AllThreadsSyscall6(unix.SYS_PRCTL, unix.PR_CAPBSET_DROP, uintptr(capability), 0, 0, 0, 0); err != 0 && err != unix.EINVAL {
			return fail()
		}
	}
	capabilities := [2]unix.CapUserData{}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	_, _, capErr := syscall.AllThreadsSyscall(unix.SYS_CAPSET, uintptr(unsafe.Pointer(&header)), uintptr(unsafe.Pointer(&capabilities[0])), 0)
	runtime.KeepAlive(header)
	runtime.KeepAlive(capabilities)
	if capErr != 0 {
		return fail()
	}
	for resource, limit := range map[int]uint64{unix.RLIMIT_CORE: 0, unix.RLIMIT_FSIZE: 0, unix.RLIMIT_NOFILE: 64, unix.RLIMIT_RTPRIO: 0} {
		if unix.Setrlimit(resource, &unix.Rlimit{Cur: limit, Max: limit}) != nil {
			return fail()
		}
	}
	unix.Close(5)
	unix.Close(6)
	lifetime, ready := os.NewFile(3, "router-lifetime"), os.NewFile(4, "router-ready")
	defer lifetime.Close()
	defer ready.Close()
	if ready.SetWriteDeadline(time.Now().Add(5*time.Second)) != nil {
		return fail()
	}
	if n, err := ready.Write([]byte{'r'}); err != nil || n != 1 || ready.Close() != nil {
		return fail()
	}
	// EOF is termination; any byte is invalid. No unbounded input accumulation.
	var token [1]byte
	if n, err := lifetime.Read(token[:]); n != 0 || err != io.EOF {
		return fail()
	}
	return 0
}

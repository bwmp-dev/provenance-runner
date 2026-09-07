//go:build linux

package gvisor

import (
	"fmt"
	"github.com/bwmp-dev/provenance-runner/internal/runtimeidentity"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const MeasuredLauncherCommand = "__gvisor-measured-launch"
const MeasuredChildCommand = "__gvisor-measured-child"

var retainedReference = regexp.MustCompile(`^/proc/[1-9][0-9]*/fd/[0-9]+$`)

// RunMeasuredLauncher preserves scope membership while creating only a private
// caller-mapped user/mount namespace. No host capability is acquired. Its child
// executes the retained runner and sandbox objects, not configured pathnames.
func RunMeasuredLauncher(arguments []string, stderr io.Writer) int {
	if os.Getuid() == 0 || os.Geteuid() != os.Getuid() || os.Getegid() != os.Getgid() {
		fmt.Fprintln(stderr, "measured launcher requires an unprivileged caller")
		return runscFailureExitCode
	}
	if len(arguments) < 8 || !retainedReference.MatchString(arguments[0]) || !retainedReference.MatchString(arguments[1]) || !retainedReference.MatchString(arguments[2]) || !retainedReference.MatchString(arguments[3]) || !filepath.IsAbs(arguments[4]) || filepath.Clean(arguments[4]) != arguments[4] || filepath.Base(arguments[4]) != ".measured-root" || arguments[6] != "embedded-executable" || arguments[7] != "--" || !embeddedOptions(arguments[8:]) {
		fmt.Fprintln(stderr, "invalid measured launcher inputs")
		return runscFailureExitCode
	}
	files := make([]*os.File, 0, 5)
	defer func() {
		for _, file := range files {
			_ = file.Close()
		}
	}()
	for index, path := range []string{arguments[0], arguments[1], "/proc/self/exe", arguments[2], arguments[3]} {
		flags := os.O_RDONLY
		if index == 0 {
			flags = unix.O_PATH | unix.O_DIRECTORY
		}
		file, err := os.OpenFile(path, flags, 0)
		if err != nil {
			fmt.Fprintln(stderr, "measured launcher identity unavailable")
			return runscFailureExitCode
		}
		files = append(files, file)
	}
	args := append([]string{MeasuredChildCommand, arguments[4], arguments[5], arguments[6], "--"}, arguments[8:]...)
	child := exec.Command("/proc/self/fd/5", args...)
	child.ExtraFiles = files
	child.Stdout, child.Stderr = os.Stdout, stderr
	child.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 unix.CLONE_NEWUSER | unix.CLONE_NEWNS,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
		Pdeathsig:                  syscall.SIGKILL,
	}
	if err := child.Start(); err != nil {
		fmt.Fprintln(stderr, "measured namespace unavailable")
		return runscFailureExitCode
	}
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	for {
		select {
		case <-signals:
			_ = child.Process.Signal(syscall.SIGTERM)
		case err := <-done:
			if err == nil {
				return 0
			}
			if child.ProcessState != nil && child.ProcessState.ExitCode() >= 0 {
				return child.ProcessState.ExitCode()
			}
			return runscFailureExitCode
		}
	}
}

// RunMeasuredChild runs only in the fresh mapped namespace. The bind mount dies
// with this namespace; it never publishes a host mount or changes a rootfs.
func RunMeasuredChild(arguments []string, stderr io.Writer) int {
	stage := "inputs"
	fail := func() int {
		fmt.Fprintln(stderr, "measured mount handoff refused:", stage)
		return runscFailureExitCode
	}
	if len(arguments) < 4 || arguments[2] != "embedded-executable" || arguments[3] != "--" || !filepath.IsAbs(arguments[0]) || filepath.Clean(arguments[0]) != arguments[0] || filepath.Base(arguments[0]) != ".measured-root" || os.Getuid() != 0 || !embeddedOptions(arguments[4:]) {
		return fail()
	}
	// Require the exact one-ID mapping established by the trusted parent.
	stage = "mapping"
	for _, path := range []string{"/proc/self/uid_map", "/proc/self/gid_map"} {
		data, err := os.ReadFile(path)
		if err != nil {
			return fail()
		}
		if !singleCallerMapping(data) {
			return fail()
		}
	}
	var source, target unix.Stat_t
	stage = "source"
	if unix.Fstat(3, &source) != nil || source.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fail()
	}
	stage = "target"
	if unix.Lstat(arguments[0], &target) != nil || target.Mode&unix.S_IFMT != unix.S_IFDIR || target.Uid != 0 || target.Mode&0077 != 0 {
		return fail()
	}
	stage = "mount_private"
	if unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, "") != nil {
		return fail()
	}
	stage = "mount_clone"
	root, image, loop := os.NewFile(3, "root"), os.NewFile(6, "image"), os.NewFile(7, "loop")
	defer root.Close()
	defer image.Close()
	defer loop.Close()
	if runtimeidentity.CloneIntoNamespace(root, image, loop, arguments[1], arguments[0]) != nil {
		return fail()
	}
	var fs unix.Statfs_t
	stage = "mounted_identity"
	if unix.Stat(arguments[0], &target) != nil || source.Dev != target.Dev || source.Ino != target.Ino || unix.Statfs(arguments[0], &fs) != nil || fs.Type != unix.SQUASHFS_MAGIC || fs.Flags&unix.ST_RDONLY == 0 {
		return fail()
	}
	stage = "embedded_selection"
	sidecars := filepath.Join(filepath.Dir(arguments[0]), ".measured-sidecars")
	if os.Mkdir(sidecars, 0700) != nil {
		return fail()
	}
	if unix.Mount("tmpfs", sidecars, "tmpfs", unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "size=4096,mode=0555") != nil {
		return fail()
	}
	if unix.Statfs(sidecars, &fs) != nil || fs.Type != unix.TMPFS_MAGIC || fs.Flags&unix.ST_RDONLY == 0 {
		return fail()
	}
	entries, err := os.ReadDir(sidecars)
	if err != nil || len(entries) != 0 {
		return fail()
	}
	environment := append(os.Environ(), "GVISOR_SIDECAR_BINARIES_DIR="+sidecars)
	// CLOEXEC prevents evidence/root/runner descriptors leaking into the guest
	// runtime; /proc/self/fd/4 is resolved atomically by exec before it closes.
	for _, fd := range []int{3, 4, 5, 6, 7} {
		unix.CloseOnExec(fd)
	}
	args := append([]string{"/proc/self/fd/4"}, arguments[4:]...)
	stage = "exec"
	if syscall.Exec(args[0], args, environment) != nil {
		return fail()
	}
	return 0
}

func embeddedOptions(arguments []string) bool {
	if os.Getenv("GVISOR_SIDECAR_BINARIES_DIR") != "" || os.Getenv("GVISOR_ENFORCE_RELEASE") != "" {
		return false
	}
	operation := ""
	networkNone := false
	for _, argument := range arguments {
		// Never override an explicitly selected STRICT/release policy or select
		// checkpoint/helper-dependent operations through the measured launcher.
		if strings.HasPrefix(argument, "--sidecar-") {
			return false
		}
		if strings.HasPrefix(argument, "--network") && (argument == "--network" || strings.HasPrefix(argument, "--network=")) {
			if argument != "--network=none" || networkNone || operation != "" {
				return false
			}
			networkNone = true
		}
		if operation == "" && !strings.HasPrefix(argument, "--") {
			operation = argument
		}
	}
	return operation == "run" && networkNone
}

func singleCallerMapping(data []byte) bool {
	fields := strings.Fields(string(data))
	if len(fields) != 3 || fields[0] != "0" || fields[2] != "1" {
		return false
	}
	outside, err := strconv.ParseUint(fields[1], 10, 32)
	return err == nil && outside > 0 && outside < 4294967295
}

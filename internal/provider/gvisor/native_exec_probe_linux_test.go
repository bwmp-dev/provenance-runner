//go:build linux

package gvisor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Diagnostic only. The initial mapped pathname launch is NOT a production
// fallback. It lets us test native FD exec separately from procfs resolution.
func TestMeasuredNativeFDExecDiagnostic(t *testing.T) {
	if os.Getenv("PROVENANCE_MEASURED_EXEC_DIAGNOSTIC") != "1" {
		t.Skip("owned disposable diagnostic only")
	}
	if os.Getuid() == 0 {
		t.Fatal("requires owned nonroot caller")
	}
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "-test.run=^TestMeasuredNativeFDExecChild$", "-test.count=1", "-test.v")
	cmd.ExtraFiles = []*os.File{file}
	cmd.Env = append(os.Environ(), "PROVENANCE_NATIVE_EXEC_PHASE=bootstrap")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS, UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}, GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}, GidMappingsEnableSetgroups: false, Pdeathsig: syscall.SIGKILL}
	output, err := cmd.CombinedOutput()
	category := "none"
	if err != nil {
		category = namespaceFailureCategory(err)
		for _, value := range []string{"permission", "access", "unsupported", "invalid", "resources", "capacity", "other"} {
			if bytes.Contains(output, []byte("NATIVE_EXEC_ERROR_"+value)) {
				category = value
			}
		}
	}
	record, _ := json.Marshal(map[string]any{"version": 1, "mapped": true, "nativeExecveat": true, "uid": os.Getuid(), "identityPrechecked": bytes.Contains(output, []byte("NATIVE_EXEC_PRECHECK_OK")), "childConfirmed": err == nil && bytes.Contains(output, []byte("NATIVE_EXEC_SAME_OBJECT_OK")), "errorCategory": category})
	t.Log("MEASURED_NATIVE_EXEC_PROBE=" + string(record))
}

func TestMeasuredNativeFDExecChild(t *testing.T) {
	phase := os.Getenv("PROVENANCE_NATIVE_EXEC_PHASE")
	if phase != "bootstrap" && phase != "terminal" {
		t.Skip("owned diagnostic child only")
	}
	if os.Getuid() != 0 || os.Getgid() != 0 {
		t.Fatal("incorrect mapped identity")
	}
	retained := os.NewFile(3, "retained-probe")
	defer retained.Close()
	actual, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal("actual executable unavailable")
	}
	defer actual.Close()
	left, err := retained.Stat()
	if err != nil {
		t.Fatal("retained stat unavailable")
	}
	right, err := actual.Stat()
	if err != nil || !os.SameFile(left, right) {
		t.Fatal("executable identity substituted")
	}
	hashFile := func(f *os.File) []byte {
		h := sha256.New()
		if _, err := io.Copy(h, io.NewSectionReader(f, 0, left.Size())); err != nil {
			t.Fatal("executable hash unavailable")
		}
		return h.Sum(nil)
	}
	if !bytes.Equal(hashFile(retained), hashFile(actual)) {
		t.Fatal("executable bytes substituted")
	}
	if phase == "terminal" {
		fmt.Println("NATIVE_EXEC_SAME_OBJECT_OK")
		return
	}
	environment := []string{}
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "PROVENANCE_NATIVE_EXEC_PHASE=") {
			environment = append(environment, entry)
		}
	}
	environment = append(environment, "PROVENANCE_NATIVE_EXEC_PHASE=terminal")
	arguments := []string{"retained-native-probe", "-test.run=^TestMeasuredNativeFDExecChild$", "-test.count=1", "-test.v"}
	fmt.Println("NATIVE_EXEC_PRECHECK_OK")
	err = nativeProbeExec(3, arguments, environment)
	t.Fatal("NATIVE_EXEC_ERROR_" + namespaceFailureCategory(err))
}

func nativeProbeExec(fd int, args, env []string) error {
	pointers := func(values []string) ([]*byte, error) {
		result := make([]*byte, len(values)+1)
		for i, value := range values {
			p, err := syscall.BytePtrFromString(value)
			if err != nil {
				return nil, err
			}
			result[i] = p
		}
		return result, nil
	}
	argv, err := pointers(args)
	if err != nil {
		return err
	}
	environ, err := pointers(env)
	if err != nil {
		return err
	}
	empty := []byte{0}
	_, _, errno := unix.RawSyscall6(unix.SYS_EXECVEAT, uintptr(fd), uintptr(unsafe.Pointer(&empty[0])), uintptr(unsafe.Pointer(&argv[0])), uintptr(unsafe.Pointer(&environ[0])), unix.AT_EMPTY_PATH, 0)
	runtime.KeepAlive(argv)
	runtime.KeepAlive(environ)
	runtime.KeepAlive(empty)
	return errno
}

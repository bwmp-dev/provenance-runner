//go:build linux

package gvisor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
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
	for _, native := range []bool{false, true} {
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
		cmd.Env = append(os.Environ(), "PROVENANCE_NATIVE_EXEC_PHASE=bootstrap", fmt.Sprintf("PROVENANCE_NATIVE_EXEC_METHOD=%t", native))
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS, UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}, GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}, GidMappingsEnableSetgroups: false, Pdeathsig: syscall.SIGKILL}
		output, err := cmd.CombinedOutput()
		category := "none"
		stage := "complete"
		if err != nil {
			stage = "launch_or_child"
			category = namespaceFailureCategory(err)
			for _, value := range []string{"permission", "access", "unsupported", "invalid", "resources", "capacity", "other"} {
				if bytes.Contains(output, []byte("NATIVE_EXEC_ERROR_"+value)) {
					category = value
				}
			}
		}
		for _, value := range []string{"mapped_identity", "actual_open", "retained_stat", "actual_stat", "object_identity", "retained_hash", "actual_hash", "hash_identity", "execveat", "proc_exec"} {
			if bytes.Contains(output, []byte("NATIVE_EXEC_STAGE_"+value)) {
				stage = value
			}
		}
		confinement := "unavailable"
		for _, value := range []string{"unconfined", "confined"} {
			if bytes.Contains(output, []byte("NATIVE_EXEC_CONFINEMENT_"+value)) {
				confinement = value
			}
		}
		var attribution map[string]string
		for _, line := range strings.Split(string(output), "\n") {
			if strings.HasPrefix(line, "NATIVE_FD_ATTRIBUTION=") {
				_ = json.Unmarshal([]byte(strings.TrimPrefix(line, "NATIVE_FD_ATTRIBUTION=")), &attribution)
				break
			}
		}
		record, _ := json.Marshal(map[string]any{"version": 1, "goVersion": runtime.Version(), "descriptorAttribution": attribution, "confinement": confinement, "stage": stage, "mapped": true, "pathnameBootstrap": true, "nativeExecveat": native, "uid": os.Getuid(), "identityPrechecked": bytes.Contains(output, []byte("NATIVE_EXEC_PRECHECK_OK")), "childConfirmed": err == nil && bytes.Contains(output, []byte("NATIVE_EXEC_SAME_OBJECT_OK")), "errorCategory": category})
		t.Log("MEASURED_NATIVE_EXEC_PROBE=" + string(record))
	}
}

func TestMeasuredNativeFDExecChild(t *testing.T) {
	phase := os.Getenv("PROVENANCE_NATIVE_EXEC_PHASE")
	if phase != "bootstrap" && phase != "terminal" {
		t.Skip("owned diagnostic child only")
	}
	if os.Getuid() != 0 || os.Getgid() != 0 {
		t.Fatal("NATIVE_EXEC_STAGE_mapped_identity")
	}
	attributes, _ := json.Marshal(nativeDescriptorAttribution())
	fmt.Println("NATIVE_FD_ATTRIBUTION=" + string(attributes))
	if value, err := os.ReadFile("/proc/self/attr/current"); err == nil {
		if strings.TrimSpace(string(value)) == "unconfined" {
			fmt.Println("NATIVE_EXEC_CONFINEMENT_unconfined")
		} else {
			fmt.Println("NATIVE_EXEC_CONFINEMENT_confined")
		}
	}
	retained := os.NewFile(3, "retained-probe")
	defer retained.Close()
	actual, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal("NATIVE_EXEC_STAGE_actual_open NATIVE_EXEC_ERROR_" + namespaceFailureCategory(err))
	}
	defer actual.Close()
	left, err := retained.Stat()
	if err != nil {
		t.Fatal("NATIVE_EXEC_STAGE_retained_stat NATIVE_EXEC_ERROR_" + namespaceFailureCategory(err))
	}
	right, err := actual.Stat()
	if err != nil {
		t.Fatal("NATIVE_EXEC_STAGE_actual_stat NATIVE_EXEC_ERROR_" + namespaceFailureCategory(err))
	}
	if !os.SameFile(left, right) {
		t.Fatal("NATIVE_EXEC_STAGE_object_identity")
	}
	hashFile := func(f *os.File, stage string) []byte {
		h := sha256.New()
		if _, err := io.Copy(h, io.NewSectionReader(f, 0, left.Size())); err != nil {
			t.Fatal("NATIVE_EXEC_STAGE_" + stage + " NATIVE_EXEC_ERROR_" + namespaceFailureCategory(err))
		}
		return h.Sum(nil)
	}
	if !bytes.Equal(hashFile(retained, "retained_hash"), hashFile(actual, "actual_hash")) {
		t.Fatal("NATIVE_EXEC_STAGE_hash_identity")
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
	if os.Getenv("PROVENANCE_NATIVE_EXEC_METHOD") == "true" {
		err = nativeProbeExec(3, arguments, environment)
		fmt.Println("NATIVE_EXEC_STAGE_execveat")
	} else {
		err = syscall.Exec("/proc/self/fd/3", arguments, environment)
		fmt.Println("NATIVE_EXEC_STAGE_proc_exec")
	}
	t.Fatal("NATIVE_EXEC_ERROR_" + namespaceFailureCategory(err))
}

func nativeDescriptorAttribution() map[string]string {
	closedErr := func(err error) string {
		if err == nil {
			return "none"
		}
		if errors.Is(err, syscall.EBADF) {
			return "bad_descriptor"
		}
		return namespaceFailureCategory(err)
	}
	result := map[string]string{}
	target, err := os.Readlink("/proc/self/fd/3")
	result["readlinkError"] = closedErr(err)
	actualPath, actualErr := os.Readlink("/proc/self/exe")
	result["target"] = "other"
	if err == nil {
		switch target {
		case "apparmor/.null", "/apparmor/.null", "apparmor/.null (deleted)", "/apparmor/.null (deleted)":
			result["target"] = "apparmor-null"
		default:
			if actualErr == nil && target == actualPath {
				result["target"] = "expected"
			}
		}
	}
	_, err = unix.FcntlInt(3, unix.F_GETFD, 0)
	result["getfdError"] = closedErr(err)
	var st unix.Stat_t
	result["rawFstatError"] = closedErr(unix.Fstat(3, &st))
	actual, err := os.Open("/proc/self/exe")
	result["freshOpenError"] = closedErr(err)
	result["freshStatError"] = "unavailable"
	if err == nil {
		_, err = actual.Stat()
		result["freshStatError"] = closedErr(err)
		actual.Close()
	}
	result["profile"] = "unavailable"
	if value, err := os.ReadFile("/proc/self/attr/current"); err == nil {
		profile := strings.TrimSpace(string(value))
		switch profile {
		case "unconfined":
			result["profile"] = "unconfined"
		case "unprivileged_userns", "unprivileged_userns (enforce)", "unprivileged_userns (complain)":
			result["profile"] = "unprivileged_userns"
		default:
			result["profile"] = "other"
		}
	}
	return result
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

// Package runtimeidentity binds observed runtime objects to an execution.
// It trusts the host kernel and privileged provisioning, not supplied labels.
package runtimeidentity

import (
	"errors"
	"regexp"
)

var ErrUnavailable = errors.New("runtime measurement unavailable")
var ErrDrift = errors.New("runtime measurement identity changed")

type RootFS struct {
	Format string `json:"format"`
	SHA256 string `json:"sha256"`
}

// Snapshot is a value-only historical observation, never a requested image pin.
type Snapshot struct {
	RunnerVersion           string `json:"runnerVersion"`
	RunnerExecutableSHA256  string `json:"runnerExecutableSha256"`
	SandboxKind             string `json:"sandboxKind"`
	SandboxVersion          string `json:"sandboxVersion"`
	SandboxExecutableSHA256 string `json:"sandboxExecutableSha256"`
	NetworkMode             string `json:"networkMode"`
	RootFS                  RootFS `json:"rootfs"`
}

var versionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

func (s Snapshot) Valid() bool {
	return versionPattern.MatchString(s.RunnerVersion) && versionPattern.MatchString(s.SandboxVersion) && digestPattern.MatchString(s.RunnerExecutableSHA256) && digestPattern.MatchString(s.SandboxExecutableSHA256) && s.SandboxKind == "gvisor" && s.NetworkMode == "none" && s.RootFS.Format == "squashfs-image-sha256/v1" && digestPattern.MatchString(s.RootFS.SHA256)
}

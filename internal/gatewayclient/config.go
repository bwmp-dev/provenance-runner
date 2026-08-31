package gatewayclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	ConfigSchemaVersion      = "provenance.runner-connect/v1alpha1"
	ProtocolVersion          = "1"
	MaximumConfigBytes       = 64 << 10
	MaximumCredentialBytes   = 4096
	MaximumMessageBytes      = 64 << 10
	maximumIdentifierBytes   = 128
	maximumCPUCapacityMillis = 128_000
	maximumMemoryCapacity    = 1 << 40
	maximumDiskCapacity      = 16 << 40
	maximumProcessCount      = 1 << 20
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*$`)
var versionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+:/-]*$`)
var uuidPattern = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)

type ScopeKind string

const (
	ScopePlatform     ScopeKind = "platform"
	ScopeOrganization ScopeKind = "organization"
)

type ExpectedScope struct {
	Kind           ScopeKind `json:"kind"`
	OrganizationID string    `json:"organizationId,omitempty"`
}

type Resources struct {
	CPUMillis    uint32 `json:"cpuMillis"`
	MemoryBytes  uint64 `json:"memoryBytes"`
	DiskBytes    uint64 `json:"diskBytes"`
	ProcessCount uint32 `json:"processCount"`
}

type Config struct {
	SchemaVersion  string        `json:"schemaVersion"`
	GatewayAddress string        `json:"gatewayAddress"`
	RunnerID       string        `json:"runnerId"`
	InstanceID     string        `json:"instanceId"`
	CredentialFile string        `json:"credentialFile"`
	ExpectedScope  ExpectedScope `json:"expectedScope"`
	Resources      Resources     `json:"resources"`

	RunnerVersion string `json:"-"`
	credential    []byte
}

func LoadConfig(path, runnerVersion string) (Config, error) {
	data, err := readRegularFile(path, MaximumConfigBytes, false)
	if err != nil {
		return Config{}, fmt.Errorf("read connect config: %w", err)
	}
	config, err := decodeConfig(data)
	if err != nil {
		return Config{}, err
	}
	config = config.normalized()
	config.RunnerVersion = runnerVersion
	if !filepath.IsAbs(config.CredentialFile) {
		config.CredentialFile = filepath.Join(filepath.Dir(path), config.CredentialFile)
	}
	credential, err := readRegularFile(config.CredentialFile, MaximumCredentialBytes, true)
	if err != nil {
		return Config{}, fmt.Errorf("read connection credential: %w", err)
	}
	if len(credential) == 0 {
		return Config{}, errors.New("connection credential is empty")
	}
	config.credential = credential
	if err := config.validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func decodeConfig(data []byte) (Config, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("decode connect config: %w", err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return Config{}, errors.New("decode connect config: multiple JSON values are not allowed")
		}
		return Config{}, fmt.Errorf("decode trailing connect config: %w", err)
	}
	if err := config.validatePublic(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (c Config) validate() error {
	if err := c.validatePublic(); err != nil {
		return err
	}
	if len(c.RunnerVersion) == 0 || len(c.RunnerVersion) > 128 || !versionPattern.MatchString(c.RunnerVersion) {
		return errors.New("runnerVersion must contain between 1 and 128 supported characters")
	}
	if len(c.credential) == 0 || len(c.credential) > MaximumCredentialBytes {
		return fmt.Errorf("connection credential must contain between 1 and %d bytes", MaximumCredentialBytes)
	}
	return nil
}

func (c Config) validatePublic() error {
	if c.SchemaVersion != ConfigSchemaVersion {
		return fmt.Errorf("schemaVersion must be %q", ConfigSchemaVersion)
	}
	if err := validateGatewayAddress(c.GatewayAddress); err != nil {
		return err
	}
	if err := validateUUID("runnerId", c.RunnerID); err != nil {
		return err
	}
	if err := validateBoundedText("instanceId", c.InstanceID, 1, maximumIdentifierBytes); err != nil {
		return err
	}
	if strings.TrimSpace(c.CredentialFile) == "" {
		return errors.New("credentialFile is required")
	}
	if len(c.CredentialFile) > 4096 {
		return errors.New("credentialFile must be at most 4096 bytes")
	}
	switch c.ExpectedScope.Kind {
	case ScopePlatform:
		if c.ExpectedScope.OrganizationID != "" {
			return errors.New("expectedScope.organizationId must be empty for platform scope")
		}
	case ScopeOrganization:
		if err := validateUUID("expectedScope.organizationId", c.ExpectedScope.OrganizationID); err != nil {
			return err
		}
	default:
		return errors.New("expectedScope.kind must be platform or organization")
	}
	if c.Resources.CPUMillis == 0 || c.Resources.CPUMillis > maximumCPUCapacityMillis {
		return fmt.Errorf("resources.cpuMillis must be between 1 and %d", maximumCPUCapacityMillis)
	}
	if c.Resources.MemoryBytes == 0 || c.Resources.MemoryBytes > maximumMemoryCapacity {
		return fmt.Errorf("resources.memoryBytes must be between 1 and %d", maximumMemoryCapacity)
	}
	if c.Resources.DiskBytes == 0 || c.Resources.DiskBytes > maximumDiskCapacity {
		return fmt.Errorf("resources.diskBytes must be between 1 and %d", maximumDiskCapacity)
	}
	if c.Resources.ProcessCount == 0 || c.Resources.ProcessCount > maximumProcessCount {
		return fmt.Errorf("resources.processCount must be between 1 and %d", maximumProcessCount)
	}
	return nil
}

func (c Config) normalized() Config {
	c.RunnerID = strings.ToLower(c.RunnerID)
	if c.ExpectedScope.Kind == ScopeOrganization {
		c.ExpectedScope.OrganizationID = strings.ToLower(c.ExpectedScope.OrganizationID)
	}
	return c
}

func validateGatewayAddress(address string) error {
	if address != strings.TrimSpace(address) || strings.Contains(address, "://") {
		return errors.New("gatewayAddress must be a host:port authority without a URL scheme")
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil || !validHost(host) {
		return errors.New("gatewayAddress must be a host:port authority without a URL scheme")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return errors.New("gatewayAddress port must be between 1 and 65535")
	}
	return nil
}

func validHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func validateIdentifier(field, value string, maximum int) error {
	if value == "" {
		return fmt.Errorf("%s is required", field)
	}
	if len(value) > maximum {
		return fmt.Errorf("%s must be at most %d bytes", field, maximum)
	}
	if !identifierPattern.MatchString(value) {
		return fmt.Errorf("%s contains unsupported characters", field)
	}
	return nil
}

func validateUUID(field, value string) error {
	if !uuidPattern.MatchString(value) {
		return fmt.Errorf("%s must be a UUID", field)
	}
	return nil
}

func validateBoundedText(field, value string, minimum, maximum int) error {
	if !utf8.ValidString(value) || len(value) < minimum || len(value) > maximum || strings.TrimSpace(value) != value {
		return fmt.Errorf("%s must be valid trimmed UTF-8 containing %d to %d bytes", field, minimum, maximum)
	}
	return nil
}

func readRegularFile(path string, maximum int64, private bool) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, errors.New("file must be a regular file and not a symbolic link")
	}
	if private && !privateFileMode(before.Mode().Perm()) {
		return nil, errors.New("file permissions must be owner-readable and must not grant execute, group, or other access")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, errors.New("file changed while it was opened")
	}
	if private && !privateFileMode(after.Mode().Perm()) {
		return nil, errors.New("file permissions must be owner-readable and must not grant execute, group, or other access")
	}
	if after.Size() > maximum {
		return nil, fmt.Errorf("file exceeds %d bytes", maximum)
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, fmt.Errorf("file exceeds %d bytes", maximum)
	}
	return data, nil
}

func privateFileMode(mode os.FileMode) bool {
	return mode&0o400 != 0 && mode&^os.FileMode(0o600) == 0
}

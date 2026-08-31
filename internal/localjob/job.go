package localjob

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"
)

const SchemaVersion = "provenance.local-job/v1alpha1"

const (
	DefaultTimeout        = 5 * time.Minute
	MaximumTimeout        = time.Hour
	DefaultMaxOutputBytes = 1 << 20
	MaximumOutputBytes    = 16 << 20
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*$`)

type Job struct {
	SchemaVersion       string          `json:"schemaVersion"`
	ID                  string          `json:"id"`
	Provider            string          `json:"provider"`
	TimeoutMilliseconds int64           `json:"timeoutMilliseconds,omitempty"`
	MaxOutputBytes      int64           `json:"maxOutputBytes,omitempty"`
	Environment         json.RawMessage `json:"environment"`
}

func Decode(data []byte) (Job, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var job Job
	if err := decoder.Decode(&job); err != nil {
		return Job{}, fmt.Errorf("decode job: %w", err)
	}

	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return Job{}, errors.New("decode job: multiple JSON values are not allowed")
		}
		return Job{}, fmt.Errorf("decode trailing data: %w", err)
	}

	if err := job.Validate(); err != nil {
		return Job{}, err
	}
	return job, nil
}

func (j Job) Validate() error {
	if j.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schemaVersion must be %q", SchemaVersion)
	}
	if err := validateIdentifier("id", j.ID, 128); err != nil {
		return err
	}
	if err := validateIdentifier("provider", j.Provider, 64); err != nil {
		return err
	}
	if j.TimeoutMilliseconds < 0 || j.TimeoutMilliseconds > MaximumTimeout.Milliseconds() {
		return fmt.Errorf("timeoutMilliseconds must be between 1 and %d when set", MaximumTimeout.Milliseconds())
	}
	if j.MaxOutputBytes < 0 || j.MaxOutputBytes > MaximumOutputBytes {
		return fmt.Errorf("maxOutputBytes must be between 1 and %d when set", MaximumOutputBytes)
	}
	if len(j.Environment) == 0 || bytes.Equal(bytes.TrimSpace(j.Environment), []byte("null")) {
		return errors.New("environment is required")
	}
	return nil
}

func (j Job) Timeout() time.Duration {
	if j.TimeoutMilliseconds == 0 {
		return DefaultTimeout
	}
	return time.Duration(j.TimeoutMilliseconds) * time.Millisecond
}

func (j Job) OutputLimit() int64 {
	if j.MaxOutputBytes == 0 {
		return DefaultMaxOutputBytes
	}
	return j.MaxOutputBytes
}

func validateIdentifier(field, value string, maximumLength int) error {
	if value == "" {
		return fmt.Errorf("%s is required", field)
	}
	if len(value) > maximumLength {
		return fmt.Errorf("%s must be at most %d bytes", field, maximumLength)
	}
	if !identifierPattern.MatchString(value) {
		return fmt.Errorf("%s contains unsupported characters", field)
	}
	return nil
}

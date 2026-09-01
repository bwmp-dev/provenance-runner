package evidence

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	DefaultMaxLineBytes  int64 = 16 << 10
	DefaultMaxTotalBytes int64 = 1 << 20
	// Complete logs are retained independently from the bounded live stdout and
	// stderr projection. Keep the archive ceiling process-local and bounded even
	// when a caller asks for a much smaller live-output limit.
	DefaultMaxCompleteLogBytes int64 = 16 << 20
	DefaultMaxEvents                 = 1_024
	DefaultMaxEventBytes       int64 = 64 << 10
	MaximumLineBytes           int64 = 1 << 20
	MaximumTotalBytes          int64 = 64 << 20
	MaximumCompleteLogBytes    int64 = 16 << 20
	MaximumEvents                    = 1_024
	MaximumEventBytes          int64 = 64 << 10
)

const (
	RedactionMarker       = "[REDACTED]"
	LineTruncationMarker  = "[... line truncated ...]"
	TotalTruncationMarker = "[... output truncated ...]"
)

type Stream string

const (
	StreamStdout Stream = "stdout"
	StreamStderr Stream = "stderr"
)

type Config struct {
	MaxLineBytes         int64
	MaxTotalBytes        int64
	MaxCompleteLogBytes  int64
	MaxEvents            int
	MaxEventBytes        int64
	Secrets              []string
	StructuredLinePrefix string
	StructuredLineKind   string
}

func ValidateConfig(config Config) error {
	_, err := config.withDefaults()
	return err
}

func (c Config) withDefaults() (Config, error) {
	if c.MaxLineBytes < 0 || c.MaxTotalBytes < 0 || c.MaxCompleteLogBytes < 0 || c.MaxEvents < 0 || c.MaxEventBytes < 0 {
		return Config{}, errors.New("evidence limits cannot be negative")
	}
	if c.MaxLineBytes == 0 {
		c.MaxLineBytes = DefaultMaxLineBytes
	}
	if c.MaxTotalBytes == 0 {
		c.MaxTotalBytes = DefaultMaxTotalBytes
	}
	if c.MaxCompleteLogBytes == 0 {
		c.MaxCompleteLogBytes = DefaultMaxCompleteLogBytes
	}
	if c.MaxEvents == 0 {
		c.MaxEvents = DefaultMaxEvents
	}
	if c.MaxEventBytes == 0 {
		c.MaxEventBytes = DefaultMaxEventBytes
	}
	if c.MaxLineBytes > MaximumLineBytes || c.MaxTotalBytes > MaximumTotalBytes || c.MaxCompleteLogBytes > MaximumCompleteLogBytes || c.MaxEvents > MaximumEvents || c.MaxEventBytes > MaximumEventBytes {
		return Config{}, errors.New("evidence configuration exceeds supported limits")
	}
	if c.StructuredLinePrefix == "" && c.MaxLineBytes > c.MaxTotalBytes {
		c.MaxLineBytes = c.MaxTotalBytes
	}
	if (c.StructuredLinePrefix == "") != (c.StructuredLineKind == "") {
		return Config{}, errors.New("structured line prefix and kind must be configured together")
	}
	if len(c.StructuredLinePrefix) > 128 || strings.ContainsAny(c.StructuredLinePrefix, "\r\n") || !utf8.ValidString(c.StructuredLinePrefix) {
		return Config{}, errors.New("structured line prefix is invalid")
	}
	if c.StructuredLineKind != "" {
		if err := validateEvent(EventInput{Kind: c.StructuredLineKind, Payload: json.RawMessage(`{}`)}, c.MaxEventBytes); err != nil {
			return Config{}, fmt.Errorf("structured line kind: %w", err)
		}
	}
	secretBytes := 0
	seen := make(map[string]struct{}, len(c.Secrets))
	for _, secret := range c.Secrets {
		if secret == "" {
			return Config{}, errors.New("redaction secrets cannot be empty")
		}
		if !utf8.ValidString(secret) {
			return Config{}, errors.New("redaction secrets must be valid UTF-8")
		}
		if _, exists := seen[secret]; exists {
			continue
		}
		seen[secret] = struct{}{}
		secretBytes += len(secret)
		if len(seen) > 64 || secretBytes > 64<<10 {
			return Config{}, errors.New("redaction secret configuration exceeds its limit")
		}
	}
	return c, nil
}

type EventInput struct {
	Kind    string
	Payload json.RawMessage
}

type StructuredEvent struct {
	Sequence uint64          `json:"sequence"`
	Kind     string          `json:"kind"`
	Payload  json.RawMessage `json:"payload"`
}

type CompleteLog struct {
	ContentType       string
	ContentEncoding   string
	SHA256            string
	UncompressedBytes int64
	CompressedBytes   int64
	Data              []byte
}

type Usage struct {
	RawBytesObserved     int64
	CapturedBytes        int64
	StructuredEventCount int64
	StructuredEventBytes int64
	CompleteLogBytes     int64
	CompressedLogBytes   int64
	TruncatedLineCount   int64
	OutputTruncated      bool
	EventsTruncated      bool
}

type Bundle struct {
	Stdout               string
	Stderr               string
	Events               []StructuredEvent
	CompleteLog          CompleteLog
	Usage                Usage
	StructuredEventError string
}

func validateEvent(input EventInput, maximumBytes int64) error {
	if input.Kind == "" {
		return errors.New("record structured event: kind is empty")
	}
	if len(input.Kind) > 128 {
		return errors.New("record structured event: kind exceeds 128 bytes")
	}
	if !utf8.ValidString(input.Kind) {
		return errors.New("record structured event: kind must be valid UTF-8")
	}
	if !json.Valid(input.Payload) {
		return errors.New("record structured event: payload is not valid JSON")
	}
	if int64(len(input.Payload)) > maximumBytes {
		return fmt.Errorf("record structured event: payload exceeds %d bytes", maximumBytes)
	}
	return nil
}

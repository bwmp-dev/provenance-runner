//go:build linux

package controlchannel

import (
	"bytes"
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"time"
)

const maximumSecretFiles = 64
const maximumSecretMetadata = 8192

var secretName = regexp.MustCompile(`^[a-z][a-z0-9]*([._-][a-z0-9]+)*$`)

type secretHeader struct {
	Version         int      `json:"version"`
	Names           []string `json:"names"`
	ExpiresUnixNano int64    `json:"expiresUnixNano"`
}

// ReceivedSecrets owns received descriptors, not authority. The receiver must
// verify sealed memory-file profiles and the selected job/lease/attempt before
// materialization. Neither metadata nor values may be journaled via this type.
type ReceivedSecrets struct {
	Names     []string   `json:"-"`
	Files     []*os.File `json:"-"`
	ExpiresAt time.Time  `json:"-"`
}

func (*ReceivedSecrets) String() string   { return "[received secret descriptors]" }
func (*ReceivedSecrets) GoString() string { return "[received secret descriptors]" }
func (r *ReceivedSecrets) Close() error {
	if r == nil {
		return nil
	}
	var result error
	for _, f := range r.Files {
		if f.Close() != nil {
			result = ErrChannel
		}
	}
	r.Files = nil
	return result
}

func validSecretNames(names []string) bool {
	if len(names) < 1 || len(names) > maximumSecretFiles {
		return false
	}
	previous := ""
	for _, name := range names {
		if len(name) > 63 || !secretName.MatchString(name) || name <= previous {
			return false
		}
		previous = name
	}
	return true
}
func secretDeadline(deadline time.Time) bool {
	return validDeadline(deadline) && time.Until(deadline) <= 5*time.Second
}

// SendSecrets borrows descriptors and sends one metadata packet followed by
// exact FD batches under one deadline. The caller must hold its control-writer
// lock for the whole call and authenticate the root peer before calling it.
// It is not a scheduling capability or a replacement for delivery authorization.
func SendSecrets(channel *Channel, names []string, files []*os.File, expires time.Time, last uint64, deadline time.Time) (sequence uint64, result error) {
	sequence = last
	if channel == nil {
		return sequence, ErrChannel
	}
	defer func() {
		if result != nil {
			_ = channel.Close()
		}
	}()
	if !secretDeadline(deadline) || !validSecretNames(names) || len(files) != len(names) || !expires.After(time.Now()) || expires.UnixNano() <= 0 || last == 0 || last > ^uint64(0)-5 {
		return sequence, ErrChannel
	}
	raw, err := json.Marshal(secretHeader{1, names, expires.UnixNano()})
	if err != nil || len(raw) > maximumSecretMetadata {
		return sequence, ErrChannel
	}
	sequence++
	if channel.Send(Packet{Kind: SecretDelivery, Sequence: sequence, Payload: raw}, deadline) != nil {
		return sequence, ErrChannel
	}
	for start := 0; start < len(files); start += MaximumFiles {
		sequence++
		if channel.Send(Packet{Kind: SecretDelivery, Sequence: sequence, Files: files[start:min(start+MaximumFiles, len(files))]}, deadline) != nil {
			return sequence, ErrChannel
		}
	}
	return sequence, nil
}

// ReceiveSecrets takes ownership of first.Files even on refusal. The root
// dispatcher must call it only once, after observation and before Java release,
// with names derived from the admitted selection and the current lease ceiling.
// No authority-update interleaving or per-packet deadline renewal is accepted.
func ReceiveSecrets(channel *Channel, first Packet, expectedNames []string, maximumExpiry, deadline time.Time) (accepted *ReceivedSecrets, result error) {
	r := &ReceivedSecrets{Files: first.Files}
	defer func() {
		if result != nil {
			_ = r.Close()
			if channel != nil {
				_ = channel.Close()
			}
		}
	}()
	if channel == nil || !secretDeadline(deadline) || first.Kind != SecretDelivery || first.Sequence == 0 || len(first.Files) != 0 || len(first.Payload) == 0 || len(first.Payload) > maximumSecretMetadata || !validSecretNames(expectedNames) {
		return nil, ErrChannel
	}
	var header secretHeader
	if json.Unmarshal(first.Payload, &header) != nil || header.Version != 1 || !validSecretNames(header.Names) || !slices.Equal(header.Names, expectedNames) || header.ExpiresUnixNano <= 0 {
		return nil, ErrChannel
	}
	canonical, err := json.Marshal(header)
	if err != nil || !bytes.Equal(canonical, first.Payload) {
		return nil, ErrChannel
	}
	r.ExpiresAt = time.Unix(0, header.ExpiresUnixNano)
	if !r.ExpiresAt.After(time.Now()) || r.ExpiresAt.After(maximumExpiry) {
		return nil, ErrChannel
	}
	r.Names = append([]string(nil), header.Names...)
	for len(r.Files) < len(r.Names) {
		remaining := len(r.Names) - len(r.Files)
		packet, err := channel.Receive(deadline)
		if err != nil {
			return nil, ErrChannel
		}
		r.Files = append(r.Files, packet.Files...)
		if packet.Kind != SecretDelivery || len(packet.Payload) != 0 || len(packet.Files) != min(MaximumFiles, remaining) {
			return nil, ErrChannel
		}
	}
	if !r.ExpiresAt.After(time.Now()) {
		return nil, ErrChannel
	}
	return r, nil
}

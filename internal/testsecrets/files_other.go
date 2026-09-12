//go:build !linux

package testsecrets

import "errors"

const Destination = "/run/provenance/test-secrets"

var ErrUnavailable = errors.New("test-secret memory files unavailable")

type Files struct{}
type Mount struct{ Source, Destination string }

func (*Files) Mounts() ([]Mount, error)           { return nil, ErrUnavailable }
func (*Files) RedactionValues() ([]string, error) { return nil, ErrUnavailable }
func (*Files) Close() error                       { return nil }

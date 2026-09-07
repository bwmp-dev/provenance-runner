//go:build !linux

package runtimeidentity

import "context"

type Lease struct{}

func Acquire(context.Context, string, string, string, ...string) (*Lease, error) {
	return nil, ErrUnavailable
}
func (*Lease) RunnerPath() string  { return "" }
func (*Lease) SandboxPath() string { return "" }
func (*Lease) RootPath() string    { return "" }
func (*Lease) ImagePath() string   { return "" }
func (*Lease) LoopPath() string    { return "" }
func (*Lease) Snapshot() Snapshot  { return Snapshot{} }
func (*Lease) Validate() error     { return ErrUnavailable }
func (*Lease) Close() error        { return nil }

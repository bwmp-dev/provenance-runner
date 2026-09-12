//go:build !linux

package gvisor

func (p *Provider) pruneEmptyNativeCgroups(string) error { return nil }

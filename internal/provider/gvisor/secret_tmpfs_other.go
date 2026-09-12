//go:build !linux

package gvisor

import "errors"

func (p *Provider) createSecretTmpfs(string) (string, error) {
	return "", errors.New("test-secret tmpfs requires Linux")
}

func (p *Provider) removeSecretTmpfs(string) error { return nil }

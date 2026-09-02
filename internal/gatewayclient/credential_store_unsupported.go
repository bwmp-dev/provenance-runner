//go:build !linux

package gatewayclient

import "errors"

func openDurableCredentialStore(string) (durableCredentialStore, error) {
	return nil, errors.New("durable credential replacement requires Linux")
}

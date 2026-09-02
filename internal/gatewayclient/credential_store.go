package gatewayclient

type durableCredentialStore interface {
	Replace([]byte) error
	Close() error
}

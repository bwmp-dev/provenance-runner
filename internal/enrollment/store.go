package enrollment

import (
	"crypto/sha256"

	"github.com/bwmp-dev/provenance-runner/internal/runneridentity"
)

type enrollmentStore interface {
	ReadToken() ([]byte, error)
	ReadIdentity() (runneridentity.Document, bool, error)
	WriteIdentity(runneridentity.Document) error
	CredentialExists() (bool, error)
	InstallCredential([]byte) error
	RemoveToken([sha256.Size]byte) error
	Close() error
}

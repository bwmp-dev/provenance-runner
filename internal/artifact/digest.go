package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const cacheKeyPrefix = "sha256:"

type Digest [sha256.Size]byte

func ParseSHA256(value string) (Digest, error) {
	if len(value) != sha256.Size*2 {
		return Digest{}, fmt.Errorf("parse SHA-256: digest must contain %d hexadecimal characters", sha256.Size*2)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return Digest{}, fmt.Errorf("parse SHA-256: %w", err)
	}
	var digest Digest
	copy(digest[:], decoded)
	return digest, nil
}

func SHA256(content []byte) Digest {
	return sha256.Sum256(content)
}

func (d Digest) String() string {
	return hex.EncodeToString(d[:])
}

func (d Digest) CacheKey() string {
	return cacheKeyPrefix + d.String()
}

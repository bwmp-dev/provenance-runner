//go:build !linux

package enrollment

import "errors"

func openStore(string, string, string) (enrollmentStore, error) {
	return nil, errors.New("runner enrollment requires Linux owner-only filesystem semantics")
}

//go:build !linux

package networkpolicy

import (
	"context"

	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
)

func (s *AuthorityRoute) ObserveInstalled(context.Context, *p.JobSpecification) error {
	if s != nil {
		_ = s.Withdraw()
	}
	return ErrNamespace
}

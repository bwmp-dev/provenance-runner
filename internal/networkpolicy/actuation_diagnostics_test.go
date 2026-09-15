package networkpolicy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

type diagnosticTestRoute struct {
	recordingRoute
	err error
}

func (r *diagnosticTestRoute) Apply(context.Context, FirewallChange) error { return r.err }

func TestActuationDiagnosticsNeverForwardArbitraryBackendErrors(t *testing.T) {
	for _, test := range []struct {
		err   error
		stage string
	}{
		{errors.New("secret-backend-output"), ""},
		{fmt.Errorf("secret-backend-output: %w", &actuationFailure{actuationIdentityChanged}), "kernel identity changed"},
		{&actuationFailure{actuationReadbackInvalid}, "kernel readback invalid"},
		{&actuationFailure{255}, "unknown stage"},
	} {
		session := &RouteSession{job: "10000000-0000-4000-8000-000000000001", route: &diagnosticTestRoute{err: test.err}}
		err := session.apply(context.Background(), "synthetic", routeRefresh)
		if !errors.Is(err, ErrActuation) || strings.Contains(err.Error(), "secret") || len(err.Error()) > 100 || !strings.Contains(err.Error(), test.stage) {
			t.Fatal("backend diagnostics escaped fixed stage boundary")
		}
		if test.stage == "" && err != ErrActuation {
			t.Fatal("arbitrary backend error retained")
		}
	}
}

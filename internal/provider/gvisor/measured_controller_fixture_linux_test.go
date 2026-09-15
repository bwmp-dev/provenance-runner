//go:build linux

package gvisor

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Called only from the explicitly prepared disposable measured session fixture.
func measuredControllerSessionFixture(t *testing.T, ctx context.Context, c measuredSessionConfig) (*measuredController, measuredInput) {
	t.Helper()
	config := measuredControllerConfig{Bundles: c.Launch.Bundle.owner, Uplinks: c.Uplinks, Measurement: c.Launch.Measurement, Boundary: c.Boundary, Tools: c.Tools, Resolver: c.Resolver, BundleRoot: filepath.Dir(c.Launch.PrivateRoot), MaximumInputBytes: 2 << 20}
	// PrivateRoot includes job/.measured-root; provisioning selects the parent.
	config.BundleRoot = filepath.Dir(config.BundleRoot)
	t.Run("controller-occupied-refusal", func(t *testing.T) {
		if controller, err := newMeasuredController(ctx, config); controller != nil || err == nil {
			t.Fatal("occupied journal adopted")
		}
	})
	if config.Bundles.cleanup(ctx, c.Launch.Bundle) != nil {
		t.Fatal("seed bundle retirement")
	}
	measuredControllerResourcesFixture(t, config.Boundary.maximum.Resources)
	controller, err := newMeasuredController(ctx, config)
	if controller != nil {
		t.Cleanup(func() {
			if controller.Close(context.Background()) != nil {
				t.Error("controller cleanup")
			}
		})
	}
	if err != nil {
		t.Fatal("controller recovery", err)
	}
	t.Run("controller-exclusive-admission", func(t *testing.T) {
		if second, err := newMeasuredController(ctx, config); second != nil || err == nil {
			t.Fatal("second controller admitted")
		}
		if b, err := config.Bundles.create(c.Launch.Job); b != nil || err == nil {
			t.Fatal("unowned bundle admission")
		}
		if config.Bundles.recover(ctx) == nil || config.Bundles.close() == nil {
			t.Fatal("controller journal claim bypassed")
		}
		if scope, err := config.Bundles.cgroups.Create(c.Launch.Job); scope != nil || err == nil {
			t.Fatal("controller cgroup claim bypassed")
		}
		if config.Bundles.cgroups.Close() == nil {
			t.Fatal("controller parent handle released early")
		}
	})
	input, _ := measuredFixtureInput(t, ctx)
	t.Run("controller-staging-failure", func(t *testing.T) {
		guard, err := np.NewAuthorityRoute(ctx, c.Launch.Job)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { guard.Close() })
		now := time.Now()
		receipt := &p.LeaseReconciliation{Lease: c.Launch.Job.Lease, Attempt: c.Launch.Job.Attempt, Status: p.LeaseStatus_LEASE_STATUS_ACTIVE, Phase: p.JobPhase_JOB_PHASE_RUNNING, Disposition: p.RunnerMessageDisposition_RUNNER_MESSAGE_DISPOSITION_STALE,
			NetworkAuthorityV2: &p.NetworkAuthorityV2{Policy: c.Launch.Job.Hashes.Policy, State: p.NetworkAuthorityStateV2_NETWORK_AUTHORITY_STATE_V2_CURRENT, CheckedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(40 * time.Second))}}
		if guard.Reconcile(ctx, receipt, []p.ProtocolFeature{1, 3, 9, 10}, c.Launch.Job.Lease.ExpiresAt.AsTime()) != nil {
			t.Fatal("staging fixture authority")
		}
		bad := input
		bad.SHA256[0] ^= 1
		owned, err := controller.start(ctx, c.Launch.Job, measuredGuestCommand{Command: "/smoke", Arguments: []string{"probe-confined-dns"}}, []measuredInput{bad}, guard, c.Launch.Stdin, c.Launch.Stdout, c.Launch.Stderr)
		if owned == nil || err == nil || owned.Wait(ctx) == nil || owned.Close(ctx) != nil || owned.Release(ctx) == nil {
			t.Fatal("failed staging ownership not retired")
		}
		controller.mu.Lock()
		defer controller.mu.Unlock()
		if controller.active != nil {
			t.Fatal("failed staging retained reusable slot after verified cleanup")
		}
	})
	return controller, input
}

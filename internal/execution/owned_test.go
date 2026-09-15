package execution

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestExecuteOwnedAlwaysCollectsAndRetires(t *testing.T) {
	for _, mode := range []string{"success", "cancelled", "execution", "collection", "cleanup"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancelled" {
				cancel()
			}
			var calls []string
			prepared := &fakePrepared{
				execute: func(context.Context) (ExecutionOutcome, error) {
					calls = append(calls, "execute")
					if mode == "execution" {
						return ExecutionOutcome{}, errors.New("refused")
					}
					return ExecutionOutcome{}, nil
				},
				collect: func(ctx context.Context) (CollectedOutput, error) {
					calls = append(calls, "collect")
					if ctx.Err() != nil {
						t.Fatal("collection inherited cancellation")
					}
					if mode == "collection" {
						return CollectedOutput{}, errors.New("refused")
					}
					return CollectedOutput{Stdout: "diagnostic"}, nil
				},
				cleanup: func(ctx context.Context) error {
					calls = append(calls, "cleanup")
					if ctx.Err() != nil {
						t.Fatal("cleanup inherited cancellation")
					}
					if _, ok := ctx.Deadline(); !ok {
						t.Fatal("cleanup is unbounded")
					}
					if mode == "cleanup" {
						return errors.New("ownership retained")
					}
					return nil
				},
			}
			result := ExecuteOwned(ctx, ExecutionStart{JobID: "job", Provider: "trusted", EnvironmentIdentity: "identity"}, prepared)
			want := []string{"execute", "collect", "cleanup"}
			if mode == "cancelled" {
				want = want[1:]
			}
			if !reflect.DeepEqual(calls, want) {
				t.Fatalf("calls = %v", calls)
			}
			if result.Passed() != (mode == "success") {
				t.Fatalf("unexpected classification: %s", result.Classification)
			}
			if result.Cleanup == nil || !result.Cleanup.Attempted || result.Cleanup.Succeeded != (mode != "cleanup") {
				t.Fatal("cleanup disposition lost")
			}
			if result.MeasuredNetwork != nil || result.MeasuredRuntime != nil {
				t.Fatal("manufactured measurement")
			}
		})
	}
}

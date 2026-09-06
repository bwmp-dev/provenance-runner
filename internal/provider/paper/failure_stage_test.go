package paper

import (
	"context"
	"testing"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
	"github.com/bwmp-dev/provenance-runner/internal/localjob"
)

func TestCollectionStageComesOnlyFromValidatedClassification(t *testing.T) {
	for _, tc := range []struct {
		name, code, stage string
		want              execution.FailureStage
	}{
		{"startup", "on_enable_failure", "FAILURE_STAGE_STARTUP", execution.FailureStageStartup},
		{"wrong stage", "on_enable_failure", "FAILURE_STAGE_EXECUTION", ""},
		{"unknown stage", "on_enable_failure", "secret-stage", ""},
		{"unknown code", "secret-code", "FAILURE_STAGE_STARTUP", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := happyProbeOutput()
			failure := []execution.StructuredEvent{
				probeStructuredEvent(5, "LIFECYCLE_EXCEPTION", `{"phase":"ENABLE","plugin":"SuccessFixture"}`),
				probeStructuredEvent(6, "CLASSIFICATION", `{"code":"`+tc.code+`","category":"FAILURE_CATEGORY_PLUGIN","stage":"`+tc.stage+`","retryable":false,"plugin":"SuccessFixture"}`),
			}
			output.StructuredEvents = append(output.StructuredEvents[:4], append(failure, output.StructuredEvents[4:]...)...)
			prepared := &preparedEnvironment{delegate: &fakePrepared{output: &output}, plan: testPlan{TargetPlugin: "SuccessFixture", RequiredDependencies: []string{"DependencyFixture"}}}
			_, err := prepared.Collect(context.Background())
			if err == nil {
				t.Fatal("expected failed lifecycle")
			}
			// Use the executor's actual classification/collection path, not error-string parsing.
			registry, err := execution.NewRegistry(&stageTestProvider{prepared: prepared})
			if err != nil {
				t.Fatal(err)
			}
			executor, err := execution.NewExecutor(registry, execution.ExecutorOptions{})
			if err != nil {
				t.Fatal(err)
			}
			result := executor.Execute(context.Background(), stageTestJob())
			if result.Failure == nil || result.Failure.Stage != tc.want {
				t.Fatalf("failure=%#v", result.Failure)
			}
			if tc.want == "" && result.Failure.Code != "paper_lifecycle_failed" {
				t.Fatalf("unvalidated code escaped: %#v", result.Failure)
			}
		})
	}
}

func TestValidatedClassificationStageTable(t *testing.T) {
	for _, tc := range []struct {
		code string
		want execution.FailureStage
	}{
		{"plugin_not_found", execution.FailureStagePreparation},
		{"invalid_metadata", execution.FailureStagePreparation},
		{"missing_required_dependency", execution.FailureStagePreparation},
		{"on_load_failure", execution.FailureStageStartup},
		{"on_enable_failure", execution.FailureStageStartup},
		{"failed_required_dependency", execution.FailureStageStartup},
		{"command_assertion_failure", execution.FailureStageExecution},
		{"command_execution_failure", execution.FailureStageExecution},
		{"command_timeout", execution.FailureStageExecution},
		{"paper_lifecycle_failed", ""}, {"unknown", ""},
	} {
		if got := validatedFailureStage(tc.code); got != tc.want {
			t.Fatalf("%s stage=%s want=%s", tc.code, got, tc.want)
		}
	}
}

type stageTestProvider struct{ prepared *preparedEnvironment }

func (*stageTestProvider) Name() string { return "stage-test" }
func (p *stageTestProvider) Resolve(context.Context, execution.Request) (execution.Environment, error) {
	return &fakeSandboxEnvironment{prepared: &stageTestPrepared{paper: p.prepared}}, nil
}

type stageTestPrepared struct{ paper *preparedEnvironment }

func (*stageTestPrepared) Execute(context.Context) (execution.ExecutionOutcome, error) {
	code := 0
	return execution.ExecutionOutcome{ExitCode: &code}, nil
}
func (p *stageTestPrepared) Collect(ctx context.Context) (execution.CollectedOutput, error) {
	return p.paper.Collect(ctx)
}
func (*stageTestPrepared) Cleanup(context.Context) error { return nil }
func stageTestJob() localjob.Job {
	return localjob.Job{SchemaVersion: localjob.SchemaVersion, ID: "stage-test", Provider: "stage-test", Environment: []byte(`{}`), MaxOutputBytes: 1024}
}

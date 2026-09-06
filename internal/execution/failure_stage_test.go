package execution

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestValidatedStagePropagationAndPublicJSONCompatibility(t *testing.T) {
	for _, stage := range []FailureStage{FailureStagePreparation, FailureStageStartup, FailureStageExecution, "", "untrusted"} {
		t.Run(string(stage), func(t *testing.T) {
			err := NewStagedClassifiedError(ClassificationWorkloadFailure, "test_code", stage, errors.New("failure"))
			failure := classifyDetachedError(context.Background(), "fallback", err)
			want := stage
			if stage == "untrusted" {
				want = ""
			}
			if failure.Stage != want || failure.Code != "test_code" {
				t.Fatalf("failure=%#v", failure)
			}
			encoded, err := json.Marshal(failure)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(encoded), "stage") {
				t.Fatal("internal stage leaked into public result JSON")
			}
			var decoded Failure
			if err := json.Unmarshal([]byte(`{"classification":"workload_failure","code":"test_code","message":"failure","stage":"startup"}`), &decoded); err != nil {
				t.Fatal(err)
			}
			if decoded.Stage != "" {
				t.Fatal("public JSON supplied trusted stage")
			}
		})
	}
	if NewStagedClassifiedError(ClassificationWorkloadFailure, "test_code", FailureStageStartup, nil) != nil {
		t.Fatal("nil error changed")
	}
}

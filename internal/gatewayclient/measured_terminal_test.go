package gatewayclient

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
	"github.com/bwmp-dev/provenance-runner/internal/runtimeidentity"
	"github.com/bwmp-dev/provenance-runner/internal/terminalevidence"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestMeasuredTerminalRefusalPrecedesUploadAndJournal(t *testing.T) {
	for _, mode := range []string{"no-context", "no-v2", "no-policy", "no-authority", "forged", "ambiguous"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC()
			client, offer := activeEvidenceClient(t, now)
			raw, err := os.ReadFile("../terminalevidence/testdata/platform-created-job.json")
			if err != nil {
				t.Fatal(err)
			}
			job := new(p.JobSpecification)
			if err := protojson.Unmarshal(raw, job); err != nil {
				t.Fatal(err)
			}
			job.Lease, job.Attempt = offer.Job.Lease, offer.Job.Attempt
			terminal, err := terminalevidence.NewContextV2(job)
			if err != nil {
				t.Fatal(err)
			}
			uploader := &recordingCompleteLogUploader{object: testLogObject()}
			client.logUploader = uploader
			sent := false
			session := &clientSession{client: client, rootContext: context.Background(), authenticated: authenticatedMessage(now, nil).GetAuthenticated(), terminalEvidenceV2: true, networkFeatures: []p.ProtocolFeature{1, 3, 9, 10}, send: func(*p.RunnerMessage) error { sent = true; return nil }}
			result := execution.Result{TerminalContext: terminal, MeasuredNetwork: &runtimeidentity.NetworkObservation{}, StartedAt: now, CompletedAt: now.Add(time.Second), Classification: execution.ClassificationPassed}
			switch mode {
			case "no-context":
				result.TerminalContext = nil
			case "no-v2":
				session.terminalEvidenceV2 = false
			case "no-policy":
				session.networkFeatures = []p.ProtocolFeature{1, 3, 10}
			case "no-authority":
				session.networkFeatures = []p.ProtocolFeature{1, 3, 9}
			case "ambiguous":
				result.MeasuredRuntime = &runtimeidentity.Snapshot{}
			}
			if session.queueResult(result) == nil || uploader.calls != 0 || sent || len(client.journal.snapshot().PendingMessage) != 0 {
				t.Fatal("unproven network evidence crossed an external or durable boundary")
			}
		})
	}
}

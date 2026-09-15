//go:build linux

package gvisor

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestMeasuredBundleJournalFailsClosedWithoutOwnership(t *testing.T) {
	var j *measuredBundleJournal
	if j.recover(context.Background()) == nil || j.cleanup(context.Background(), nil) == nil || j.check(nil, nil) == nil {
		t.Fatal("missing bundle ownership accepted")
	}
	if b, err := j.create(measuredSpecJob(t)); b != nil || err == nil {
		t.Fatal("missing journal created bundle")
	}
	if j, err := openMeasuredBundleJournal(nil, nil, nil); j != nil || err == nil {
		t.Fatal("missing dedicated directories accepted")
	}
	if removeMeasuredBundleContents(context.Background(), nil, nil, 0) == nil {
		t.Fatal("missing cleanup ownership accepted")
	}
}

func TestMeasuredBundleRecordsAreCanonicalAndBounded(t *testing.T) {
	job := measuredSpecJob(t)
	r := measuredBundleRecord{Version: 1, Job: job.Lease.JobId, Lease: job.Lease.LeaseId, Execution: job.Lease.ExecutionId, Attempt: job.Attempt.AttemptId, Policy: strings.Repeat("a", 64), ParentDev: 1, ParentIno: 2, BundleDev: 1, BundleIno: 3}
	raw, _ := json.Marshal(r)
	raw = append(raw, '\n')
	name := r.Job + ".owned.json"
	if got, err := decodeMeasuredBundleRecord(raw, name, true); err != nil || got != r {
		t.Fatal("valid ownership record refused")
	}
	for _, bad := range [][]byte{nil, []byte("{}\n"), append([]byte(" "), raw...), append(raw, '\n'), []byte(strings.Replace(string(raw), "\"version\":1", "\"version\":1,\"version\":1", 1)), []byte(strings.Replace(string(raw), "\"version\":1", "\"extra\":true,\"version\":1", 1)), []byte(strings.Repeat("x", 4097))} {
		if _, err := decodeMeasuredBundleRecord(bad, name, true); err == nil {
			t.Fatal("ambiguous ownership record accepted")
		}
	}
	for _, wrong := range []string{"../" + name, "foreign.owned.json", r.Job + ".intent.json"} {
		if _, err := decodeMeasuredBundleRecord(raw, wrong, true); err == nil {
			t.Fatal("foreign record path accepted")
		}
	}
	if _, err := decodeMeasuredBundleRecord(raw, r.Job+".intent.json", false); err == nil {
		t.Fatal("owned identity mistaken for intent")
	}
}

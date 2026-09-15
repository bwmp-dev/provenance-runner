//go:build linux

package networkpolicy

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestJobCgroupJournalClosedRecords(t *testing.T) {
	id := "10000000-0000-4000-8000-000000000001"
	r := journalScopeRecord{Version: 1, Token: strings.Repeat("a", 64), Boot: id, ParentDev: 1, ParentIno: 2, Job: id, Lease: id, Execution: id, Attempt: id, Candidate: id, Matrix: id, AttemptNumber: 1, Policy: strings.Repeat("b", 64)}
	raw, _ := json.Marshal(r)
	raw = append(raw, '\n')
	name := r.Token + ".intent.json"
	if _, err := decodeScopeRecord(raw, name, false); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{string(raw[:len(raw)-1]), " " + string(raw), strings.Replace(string(raw), "\"version\":1", "\"version\":1,\"version\":1", 1), strings.Replace(string(raw), "\"version\":1", "\"version\":1,\"unknown\":true", 1), strings.Replace(string(raw), "\"scopeIno\":0", "\"scopeIno\":3", 1), strings.Repeat("x", 4097)} {
		if _, err := decodeScopeRecord([]byte(bad), name, false); err == nil {
			t.Fatal("non-canonical or malformed ownership accepted")
		}
	}
	if _, err := decodeScopeRecord(raw, "../"+name, false); err == nil {
		t.Fatal("foreign record name")
	}
	if _, err := decodeScopeRecord(raw, name, true); err == nil {
		t.Fatal("intent treated as launchable ownership")
	}
	if j, err := OpenJobCgroupJournal(nil, nil); j != nil || err == nil {
		t.Fatal("missing journal inputs")
	}
	var absent *JobCgroupJournal
	if absent.Close() != nil {
		t.Fatal("nil close")
	}
	if _, err := absent.Recover(context.Background()); err == nil {
		t.Fatal("nil recovery")
	}
}

func journalFixtureOpen(t *testing.T) *JobCgroupJournal {
	t.Helper()
	parent, err := os.Open("/sys/fs/cgroup/provenance-fixture-jobs")
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	state, err := os.Open("/state-input/journal")
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	j, err := OpenJobCgroupJournal(parent, state)
	if err != nil {
		t.Fatal("root persistent journal", err)
	}
	return j
}

func TestJobCgroupJournalCrashHelper(t *testing.T) {
	mode := os.Getenv("PROVENANCE_CGROUP_JOURNAL_CRASH")
	if mode == "" {
		t.Skip("crash helper only")
	}
	if os.Getenv("PROVENANCE_DISPOSABLE_JOB_CGROUP_FIXTURE") != "1" {
		t.Fatal("disposable fixture required")
	}
	j := journalFixtureOpen(t)
	if _, err := j.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, job, _, _, _, _ := authorityFixture(t)
	s, err := j.Create(job)
	if err != nil {
		t.Fatal(err)
	}
	if j.CheckScope(s) != nil {
		t.Fatal("durable scope rejected")
	}
	if j.CheckScope(&JobCgroup{}) == nil {
		t.Fatal("foreign scope object accepted")
	}
	if mode == "intent" {
		// Simulate the crash window before the owned marker is durable. Nothing
		// has launched; recovery must accept only an empty intended scope.
		if err := os.Remove("/state-input/journal/" + strings.TrimPrefix(s.name, "owned-") + ".owned.json"); err != nil {
			t.Fatal(err)
		}
		if j.state.Sync() != nil {
			t.Fatal("intent crash persistence")
		}
		os.Exit(73)
	}
	if mode != "owned" {
		t.Fatal("unknown crash point")
	}
	fd, err := s.LaunchFD(job)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sleep", "60")
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(fd.Fd()), Credential: &syscall.Credential{Uid: 60004, Gid: 60004}}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// Deliberately exit without any Go defers, journal cleanup or child kill.
	// The kernel releases flock, while the non-root child remains in its scope.
	os.Exit(73)
}

func TestJobCgroupJournalKernelRecovery(t *testing.T) {
	if os.Getenv("PROVENANCE_DISPOSABLE_JOB_CGROUP_FIXTURE") != "1" {
		t.Skip("explicit disposable cgroup fixture required")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil || os.Geteuid() != 0 {
		t.Fatal("fresh disposable root required")
	}
	_, job, _, _, _, _ := authorityFixture(t)
	j := journalFixtureOpen(t)
	if scope, err := j.Create(job); scope != nil || err == nil {
		t.Fatal("admission before recovery")
	}
	if _, err := j.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	unrecorded := "/sys/fs/cgroup/provenance-fixture-jobs/unrecorded-fixture"
	if err := os.Mkdir(unrecorded, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Recover(context.Background()); err == nil {
		t.Fatal("lost journal scope inventory ignored")
	}
	if _, err := os.Stat(unrecorded); err != nil {
		t.Fatal("unknown scope removed")
	}
	if err := os.Remove(unrecorded); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	parent, err := os.Open("/sys/fs/cgroup/provenance-fixture-jobs")
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	state, err := os.Open("/state-input/journal")
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	if other, err := OpenJobCgroupJournal(parent, state); other != nil || err == nil {
		if other != nil {
			other.Close()
		}
		t.Fatal("duplicate controller lock")
	}
	s, err := j.Create(job)
	if err != nil {
		t.Fatal(err)
	}
	if j.Close() == nil {
		t.Fatal("live controller released lock")
	}
	if _, err := j.Recover(context.Background()); err == nil {
		t.Fatal("recovery touched live handles")
	}
	if err := j.Cleanup(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if j.CheckScope(s) == nil {
		t.Fatal("retired scope accepted")
	}
	if err := j.Cleanup(context.Background(), s); err != nil {
		t.Fatal("durable cleanup not idempotent", err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"intent", "owned"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestJobCgroupJournalCrashHelper$")
			cmd.Env = []string{"PATH=/usr/bin:/bin", "PROVENANCE_DISPOSABLE_JOB_CGROUP_FIXTURE=1", "PROVENANCE_CGROUP_JOURNAL_CRASH=" + mode}
			raw, err := cmd.CombinedOutput()
			if err == nil || cmd.ProcessState.ExitCode() != 73 {
				t.Fatalf("forced controller crash missing: %.4096s", raw)
			}
			j := journalFixtureOpen(t)
			defer j.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			entries, err := os.ReadDir("/state-input/journal")
			if err != nil {
				t.Fatal(err)
			}
			var intent journalScopeRecord
			for _, entry := range entries {
				if strings.HasSuffix(entry.Name(), ".intent.json") {
					intent, err = j.readRecord(entry.Name(), false)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			if intent.Token == "" {
				t.Fatal("durable intent missing")
			}
			cg, err := os.Open("/sys/fs/cgroup/provenance-fixture-jobs/owned-" + intent.Token)
			if err != nil {
				t.Fatal(err)
			}
			defer cg.Close()
			if mode == "owned" {
				owned, err := j.readRecord(intent.Token+".owned.json", true)
				if err != nil {
					t.Fatal(err)
				}
				write := func(record journalScopeRecord, suffix string) {
					t.Helper()
					raw, err := json.Marshal(record)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile("/state-input/journal/"+record.Token+suffix, append(raw, '\n'), 0600); err != nil {
						t.Fatal(err)
					}
				}
				for _, kind := range []string{"boot", "parent", "scope"} {
					badIntent, badOwned := intent, owned
					switch kind {
					case "boot":
						badIntent.Boot = "90000000-0000-4000-8000-000000000001"
						badOwned.Boot = badIntent.Boot
					case "parent":
						badIntent.ParentIno++
						badOwned.ParentIno = badIntent.ParentIno
					case "scope":
						badOwned.ScopeIno++
					}
					write(badIntent, ".intent.json")
					write(badOwned, ".owned.json")
					if _, err := j.Recover(ctx); err == nil {
						t.Fatal("foreign kernel identity accepted", kind)
					}
					raw, err := readCgroupControl(cg, "cgroup.events")
					if err != nil || cgroupEmpty(raw) {
						t.Fatal("identity refusal killed live process", kind, err)
					}
					write(intent, ".intent.json")
					write(owned, ".owned.json")
				}
			} else {
				unexpected := exec.Command("/bin/sleep", "60")
				unexpected.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cg.Fd()), Credential: &syscall.Credential{Uid: 60006, Gid: 60006}}
				if err := unexpected.Start(); err != nil {
					t.Fatal(err)
				}
				if _, err := j.Recover(ctx); err == nil {
					t.Fatal("populated intent treated as owned launch")
				}
				if unexpected.Process.Signal(syscall.Signal(0)) != nil {
					t.Fatal("intent-only recovery killed unexpected process")
				}
				_ = unexpected.Process.Kill()
				_ = unexpected.Wait()
			}
			recovered, err := j.Recover(ctx)
			if err != nil || len(recovered) != 1 || recovered[0].JobID != job.Lease.JobId {
				t.Fatal("recorded recovery", err, len(recovered))
			}
			if rows, err := j.Recover(ctx); err != nil || len(rows) != 0 {
				t.Fatal("recovery replay", err)
			}
		})
	}
	// Malformed state refuses every destructive operation and new admission.
	bad := filepath.Join("/state-input/journal", strings.Repeat("c", 64)+".intent.json")
	if err := os.WriteFile(bad, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	j = journalFixtureOpen(t)
	if _, err := j.Recover(context.Background()); err == nil {
		t.Fatal("malformed record accepted")
	}
	if scope, err := j.Create(job); scope != nil || err == nil {
		t.Fatal("failed recovery admitted work")
	}
	if _, err := os.Stat(bad); err != nil {
		t.Fatal("malformed evidence deleted")
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	// This exact synthetic corrupt record was created by this test, not recovery.
	if err := os.Remove(bad); err != nil {
		t.Fatal(err)
	}
	if state.Sync() != nil {
		t.Fatal("synthetic record cleanup")
	}
	rows, err := os.ReadDir("/state-input/journal")
	if err != nil || len(rows) != 1 || rows[0].Name() != ".lock" {
		t.Fatal("journal residue", err)
	}
}

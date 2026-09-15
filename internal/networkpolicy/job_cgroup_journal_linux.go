//go:build linux

package networkpolicy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"
	"strings"
	"sync"

	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"golang.org/x/sys/unix"
)

const maxJournalScopes = 128

// JobCgroupJournal records cleanup ownership only. Recovery never restores a
// runnable scope, network authority, reservation or successful terminal result.
type JobCgroupJournal struct {
	mu                   sync.Mutex
	parent, state, lock  *os.File
	boot                 string
	parentDev, parentIno uint64
	active               map[string]*JobCgroup
	records              map[string]journalScopeRecord
	controllerResources  *ControllerResources
	ready, closed        bool
}

type journalScopeRecord struct {
	Version       int    `json:"version"`
	Token         string `json:"token"`
	Boot          string `json:"boot"`
	ParentDev     uint64 `json:"parentDev"`
	ParentIno     uint64 `json:"parentIno"`
	Job           string `json:"job"`
	Lease         string `json:"lease"`
	Execution     string `json:"execution"`
	Attempt       string `json:"attempt"`
	Candidate     string `json:"candidate"`
	Matrix        string `json:"matrix"`
	AttemptNumber uint32 `json:"attemptNumber"`
	Policy        string `json:"policy"`
	ScopeDev      uint64 `json:"scopeDev"`
	ScopeIno      uint64 `json:"scopeIno"`
}

func validJournalToken(token string) bool {
	return len(token) == 64 && strings.Trim(token, "0123456789abcdef") == ""
}
func validJournalScopeName(name string) bool {
	return strings.HasPrefix(name, "owned-") && validJournalToken(strings.TrimPrefix(name, "owned-"))
}

func kernelBootID() (string, error) {
	f, err := os.OpenFile("/proc/sys/kernel/random/boot_id", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", ErrResources
	}
	defer f.Close()
	var fs unix.Statfs_t
	if unix.Fstatfs(int(f.Fd()), &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		return "", ErrResources
	}
	raw, err := io.ReadAll(io.LimitReader(f, 38))
	if err != nil || len(raw) != 37 || raw[36] != '\n' || !validAuthorityID(string(raw[:36])) {
		return "", ErrResources
	}
	return string(raw[:36]), nil
}

func protectedJournalFile(f *os.File, directory bool) bool {
	if f == nil {
		return false
	}
	var st unix.Stat_t
	var fs unix.Statfs_t
	kind, mode := uint32(unix.S_IFREG), uint32(0600)
	if directory {
		kind = unix.S_IFDIR
		mode = 0700
	}
	if unix.Fstat(int(f.Fd()), &st) != nil || unix.Fstatfs(int(f.Fd()), &fs) != nil || st.Uid != 0 || st.Mode&unix.S_IFMT != kind || st.Mode&07777 != mode || st.Nlink == 0 || (!directory && st.Nlink != 1) {
		return false
	}
	// Persistent local filesystems only; proc/sys/cgroup/tmpfs are not journals.
	return fs.Type == unix.EXT4_SUPER_MAGIC || fs.Type == unix.XFS_SUPER_MAGIC || fs.Type == unix.BTRFS_SUPER_MAGIC
}

func journalOpenAt(state *os.File, name string, flags uint64, mode uint64) (*os.File, error) {
	if !protectedJournalFile(state, true) {
		return nil, ErrResources
	}
	fd, err := unix.Openat2(int(state.Fd()), name, &unix.OpenHow{Flags: flags | unix.O_CLOEXEC, Mode: mode, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "owned-cgroup-journal-entry")
	if !protectedJournalFile(f, false) {
		f.Close()
		return nil, ErrResources
	}
	return f, nil
}

// OpenJobCgroupJournal requires a root-private persistent state directory and an
// explicitly provisioned cgroup parent. It acquires an exclusive process lock.
// Recover must succeed before Create; closing a live journal is refused.
func OpenJobCgroupJournal(parent, state *os.File) (*JobCgroupJournal, error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || !protectedCgroup(parent, true) || !protectedJournalFile(state, true) {
		return nil, ErrResources
	}
	boot, err := kernelBootID()
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if unix.Fstat(int(parent.Fd()), &st) != nil {
		return nil, ErrResources
	}
	j := &JobCgroupJournal{boot: boot, parentDev: uint64(st.Dev), parentIno: st.Ino, active: map[string]*JobCgroup{}, records: map[string]journalScopeRecord{}}
	for _, pair := range []struct {
		from *os.File
		to   **os.File
	}{{parent, &j.parent}, {state, &j.state}} {
		fd, err := unix.FcntlInt(pair.from.Fd(), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			if j.parent != nil {
				j.parent.Close()
			}
			return nil, ErrResources
		}
		*pair.to = os.NewFile(uintptr(fd), "owned-cgroup-journal-directory")
	}
	j.lock, err = journalOpenAt(j.state, ".lock", unix.O_RDWR|unix.O_CREAT, 0600)
	if err == nil {
		err = unix.Flock(int(j.lock.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	}
	if err == nil {
		err = j.state.Sync()
	}
	if err != nil {
		if j.lock != nil {
			j.lock.Close()
		}
		j.parent.Close()
		j.state.Close()
		return nil, ErrResources
	}
	return j, nil
}

func validScopeRecord(r journalScopeRecord, owned bool) bool {
	if r.Version != 1 || !validJournalToken(r.Token) || !validJournalToken(r.Policy) || !validAuthorityID(r.Boot) || r.ParentIno == 0 || r.ParentDev == 0 || r.AttemptNumber < 1 || r.AttemptNumber > 3 {
		return false
	}
	for _, id := range []string{r.Job, r.Lease, r.Execution, r.Attempt, r.Candidate, r.Matrix} {
		if !validAuthorityID(id) {
			return false
		}
	}
	if owned {
		return r.ScopeDev != 0 && r.ScopeIno != 0
	}
	return r.ScopeDev == 0 && r.ScopeIno == 0
}

func (j *JobCgroupJournal) writeRecord(r journalScopeRecord, suffix string) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return ErrResources
	}
	raw = append(raw, '\n')
	f, err := journalOpenAt(j.state, r.Token+suffix, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0600)
	if err != nil {
		return ErrResources
	}
	n, werr := f.Write(raw)
	syncErr := f.Sync()
	closeErr := f.Close()
	dirErr := j.state.Sync()
	if n != len(raw) || werr != nil || syncErr != nil || closeErr != nil || dirErr != nil {
		return ErrResources
	}
	return nil
}

func (j *JobCgroupJournal) readRecord(name string, owned bool) (journalScopeRecord, error) {
	var r journalScopeRecord
	f, err := journalOpenAt(j.state, name, unix.O_RDONLY, 0)
	if err != nil {
		return r, ErrResources
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return r, ErrResources
	}
	return decodeScopeRecord(raw, name, owned)
}

func decodeScopeRecord(raw []byte, name string, owned bool) (journalScopeRecord, error) {
	var r journalScopeRecord
	if len(raw) > 4096 || json.Unmarshal(raw, &r) != nil || !validScopeRecord(r, owned) {
		return r, ErrResources
	}
	canonical, err := json.Marshal(r)
	if err != nil || !bytes.Equal(raw, append(canonical, '\n')) {
		return r, ErrResources
	}
	suffix := ".intent.json"
	if owned {
		suffix = ".owned.json"
	}
	if name != r.Token+suffix {
		return r, ErrResources
	}
	return r, nil
}

func (j *JobCgroupJournal) removeRecords(token string) error {
	// Sync each deletion in order: an owned-only record is never a valid crash
	// state. Intent remains until the owned marker's deletion is durable.
	for _, suffix := range []string{".owned.json", ".intent.json"} {
		err := unix.Unlinkat(int(j.state.Fd()), token+suffix, 0)
		if err != nil && err != unix.ENOENT {
			return ErrResources
		}
		if j.state.Sync() != nil {
			return ErrResources
		}
	}
	return nil
}

// Create durably records a random scope intent before mkdir and its kernel
// identity before handing out a launchable object. Partial failures stop new
// admissions and preserve records; no failed journal write grants execution.
func (j *JobCgroupJournal) Create(job *p.JobSpecification) (*JobCgroup, error) {
	return j.CreateForController(job, nil)
}

func (j *JobCgroupJournal) CreateForController(job *p.JobSpecification, resources *ControllerResources) (*JobCgroup, error) {
	if j == nil {
		return nil, ErrResources
	}
	if resources != nil && resources.Validate() != nil {
		return nil, ErrResources
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || !j.ready || j.controllerResources != resources || len(j.active) >= maxJournalScopes {
		return nil, ErrResources
	}
	owner, err := NewAuthority(job)
	if err != nil {
		return nil, ErrResources
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, ErrResources
	}
	token := hex.EncodeToString(nonce[:])
	name := "owned-" + token
	var existing unix.Stat_t
	if err := unix.Fstatat(int(j.parent.Fd()), name, &existing, unix.AT_SYMLINK_NOFOLLOW); err != unix.ENOENT {
		return nil, ErrResources
	}
	r := journalScopeRecord{Version: 1, Token: token, Boot: j.boot, ParentDev: j.parentDev, ParentIno: j.parentIno, Job: owner.lease.JobId, Lease: owner.lease.LeaseId, Execution: owner.lease.ExecutionId,
		Attempt: owner.attempt.AttemptId, Candidate: owner.attempt.ReleaseCandidateId, Matrix: owner.attempt.MatrixEntryId, AttemptNumber: owner.attempt.AttemptNumber, Policy: hex.EncodeToString(owner.digest[:])}
	if j.writeRecord(r, ".intent.json") != nil {
		j.ready = false
		return nil, ErrResources
	}
	s, err := createJobCgroup(job, j.parent, name)
	if s != nil {
		j.active[name] = s
		s.mu.Lock()
		s.journalOwner = j
		s.mu.Unlock()
	}
	if err == nil {
		var st unix.Stat_t
		if unix.Fstat(int(s.scope.Fd()), &st) != nil {
			err = ErrResources
		} else {
			r.ScopeDev = uint64(st.Dev)
			r.ScopeIno = st.Ino
			err = j.writeRecord(r, ".owned.json")
		}
	}
	if err != nil {
		j.ready = false
		if s != nil {
			s.mu.Lock()
			s.stopping = true
			s.mu.Unlock()
		}
		return s, ErrResources
	}
	j.records[name] = r
	return s, nil
}

// CheckScope verifies the exact live object and both durable records against
// the journal's original in-memory kernel identity. It grants no network access.
func (j *JobCgroupJournal) CheckScope(s *JobCgroup) error {
	if j == nil || s == nil {
		return ErrResources
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || !j.ready || j.active[s.name] != s {
		return ErrResources
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.journalOwner != j || s.journalRetired || s.removed || s.stopping {
		return ErrResources
	}
	expected, ok := j.records[s.name]
	if !ok {
		return ErrResources
	}
	owned, err := j.readRecord(expected.Token+".owned.json", true)
	if err != nil || owned != expected {
		j.ready = false
		s.stopping = true
		return ErrResources
	}
	intent, err := j.readRecord(expected.Token+".intent.json", false)
	expected.ScopeDev = 0
	expected.ScopeIno = 0
	if err != nil || intent != expected {
		j.ready = false
		s.stopping = true
		return ErrResources
	}
	return nil
}

// Cleanup removes durable ownership records only after whole-scope cleanup.
// It accepts only this live journal's exact returned object, never a label.
func (j *JobCgroupJournal) Cleanup(ctx context.Context, s *JobCgroup) error {
	if j == nil || s == nil {
		return ErrResources
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	s.mu.Lock()
	owner, retired, removed := s.journalOwner, s.journalRetired, s.removed
	s.mu.Unlock()
	if owner != j {
		return ErrResources
	}
	if retired {
		if removed {
			return nil
		}
		return ErrResources
	}
	if j.closed || j.active[s.name] != s {
		return ErrResources
	}
	if err := s.Cleanup(ctx); err != nil {
		return err
	}
	if err := j.removeRecords(strings.TrimPrefix(s.name, "owned-")); err != nil {
		j.ready = false
		return err
	}
	delete(j.active, s.name)
	delete(j.records, s.name)
	s.mu.Lock()
	s.journalRetired = true
	s.mu.Unlock()
	return nil
}

// RecoveredJobScope identifies process-scope cleanup, NOT complete job cleanup.
type RecoveredJobScope struct{ JobID, LeaseID, ExecutionID, AttemptID string }

// Recover is startup-only with no live handles. It validates every record first,
// then cleans recorded same-boot scopes by kernel identity. An intent-only scope
// must be empty: launch is forbidden until the owned marker is durable. Different
// boot or parent identities never authorize killing a currently existing scope.
func (j *JobCgroupJournal) Recover(ctx context.Context) ([]RecoveredJobScope, error) {
	if j == nil || ctx == nil {
		return nil, ErrResources
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || len(j.active) != 0 {
		return nil, ErrResources
	}
	j.ready = false
	fd, err := unix.Openat(int(j.state.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrResources
	}
	directory := os.NewFile(uintptr(fd), "owned-cgroup-journal-scan")
	entries, err := directory.ReadDir(2*maxJournalScopes + 2)
	directory.Close()
	if (err != nil && err != io.EOF) || len(entries) > 2*maxJournalScopes+1 {
		return nil, ErrResources
	}
	intents := map[string]journalScopeRecord{}
	owned := map[string]journalScopeRecord{}
	for _, entry := range entries {
		name := entry.Name()
		if name == ".lock" {
			continue
		}
		isOwned := strings.HasSuffix(name, ".owned.json")
		if entry.IsDir() || (!isOwned && !strings.HasSuffix(name, ".intent.json")) {
			return nil, ErrResources
		}
		r, err := j.readRecord(name, isOwned)
		if err != nil {
			return nil, err
		}
		if isOwned {
			owned[r.Token] = r
		} else {
			intents[r.Token] = r
		}
	}
	for token, r := range owned {
		intent, ok := intents[token]
		r.ScopeDev = 0
		r.ScopeIno = 0
		if !ok || r != intent {
			return nil, ErrResources
		}
	}
	if len(intents) > maxJournalScopes {
		return nil, ErrResources
	}
	// A lost/rolled-back journal must not make unknown live scopes invisible.
	// This parent is exclusive to this journal. Unknown directories are never
	// adopted or killed, and block all admission until explicitly resolved.
	parentFD, err := unix.Openat(int(j.parent.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrResources
	}
	parentView := os.NewFile(uintptr(parentFD), "owned-journal-parent-inventory")
	children, err := parentView.ReadDir(1025)
	parentView.Close()
	if (err != nil && err != io.EOF) || len(children) > 1024 {
		return nil, ErrResources
	}
	for _, child := range children {
		if !child.IsDir() {
			continue
		}
		name := child.Name()
		if !validJournalScopeName(name) {
			return nil, ErrResources
		}
		if _, ok := intents[strings.TrimPrefix(name, "owned-")]; !ok {
			return nil, ErrResources
		}
	}
	tokens := make([]string, 0, len(intents))
	for token := range intents {
		tokens = append(tokens, token)
	}
	sort.Strings(tokens)
	var result []RecoveredJobScope
	for _, token := range tokens {
		if ctx.Err() != nil {
			return result, errors.Join(ErrResources, ctx.Err())
		}
		r := intents[token]
		name := "owned-" + token
		fd, err := unix.Openat2(int(j.parent.Fd()), name, &unix.OpenHow{Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
		if err != nil && err != unix.ENOENT {
			return result, ErrResources
		}
		if r.Boot == j.boot && (r.ParentDev != j.parentDev || r.ParentIno != j.parentIno) {
			if fd >= 0 {
				unix.Close(fd)
			}
			return result, ErrResources
		}
		if err == nil {
			scope := os.NewFile(uintptr(fd), "recorded-job-cgroup")
			var st unix.Stat_t
			if r.Boot != j.boot || !protectedCgroup(scope, true) || unix.Fstat(fd, &st) != nil {
				scope.Close()
				return result, ErrResources
			}
			if identity, ok := owned[token]; ok {
				if identity.ScopeDev != uint64(st.Dev) || identity.ScopeIno != st.Ino {
					scope.Close()
					return result, ErrResources
				}
			} else {
				raw, err := readCgroupControl(scope, "cgroup.events")
				if err != nil || !cgroupEmpty(raw) {
					scope.Close()
					return result, ErrResources
				}
			}
			parentFD, err := unix.FcntlInt(j.parent.Fd(), unix.F_DUPFD_CLOEXEC, 0)
			if err != nil {
				scope.Close()
				return result, ErrResources
			}
			s := &JobCgroup{parent: os.NewFile(uintptr(parentFD), "recorded-job-parent"), scope: scope, name: name, stopping: true}
			err = s.Cleanup(ctx)
			if err != nil {
				scope.Close()
				s.parent.Close()
				return result, err
			}
		}
		if err := j.removeRecords(token); err != nil {
			return result, err
		}
		result = append(result, RecoveredJobScope{r.Job, r.Lease, r.Execution, r.Attempt})
	}
	j.ready = true
	return result, nil
}

// Close releases the controller lock only when it owns no live handles. Pending
// failed recovery records remain durable and may be retried by a later owner.
func (j *JobCgroupJournal) Close() error {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return nil
	}
	if len(j.active) != 0 || j.controllerResources != nil {
		return ErrResources
	}
	j.closed = true
	return errors.Join(j.lock.Close(), j.parent.Close(), j.state.Close())
}

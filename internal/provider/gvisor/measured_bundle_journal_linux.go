//go:build linux

package gvisor

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

var measuredBundleID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type measuredBundleRecord struct {
	Version   int    `json:"version"`
	Job       string `json:"job"`
	Lease     string `json:"lease"`
	Execution string `json:"execution"`
	Attempt   string `json:"attempt"`
	Policy    string `json:"policy"`
	ParentDev uint64 `json:"parentDev"`
	ParentIno uint64 `json:"parentIno"`
	BundleDev uint64 `json:"bundleDev"`
	BundleIno uint64 `json:"bundleIno"`
}

// This journal is private to the trusted controller. Its recovery first drains
// the dedicated cgroup journal, then removes only durably owned bundles. Neither
// recovery nor a bundle descriptor restores runnable authority or capacity.
type measuredBundleJournal struct {
	mu                   sync.Mutex
	parent, state, lock  *os.File
	cgroups              *np.JobCgroupJournal
	parentDev, parentIno uint64
	active               map[string]*measuredBundle
	ready, closed        bool
}

type measuredBundle struct {
	owner             *measuredBundleJournal
	record            measuredBundleRecord
	directory         *os.File
	scope             *np.JobCgroup
	retired           bool
	prepared          *measuredBundlePreparation
	preparationFailed bool
}

func (b *measuredBundle) matchesPrivateRoot(path string) bool {
	if b == nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != ".measured-root" || filepath.Base(filepath.Dir(path)) != b.record.Job {
		return false
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, filepath.Dir(path), &unix.OpenHow{Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return false
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	return unix.Fstat(fd, &st) == nil && uint64(st.Dev) == b.record.BundleDev && st.Ino == b.record.BundleIno
}

func persistentBundleFile(f *os.File, directory bool, mode uint32) bool {
	if f == nil {
		return false
	}
	var st unix.Stat_t
	var fs unix.Statfs_t
	kind := uint32(unix.S_IFREG)
	if directory {
		kind = unix.S_IFDIR
	}
	return unix.Fstat(int(f.Fd()), &st) == nil && unix.Fstatfs(int(f.Fd()), &fs) == nil &&
		st.Uid == 0 && st.Gid == 0 && st.Mode&unix.S_IFMT == kind && st.Mode&07777 == mode && st.Nlink != 0 &&
		(directory || st.Nlink == 1) && (fs.Type == unix.EXT4_SUPER_MAGIC || fs.Type == unix.XFS_SUPER_MAGIC || fs.Type == unix.BTRFS_SUPER_MAGIC)
}

func openBundleAt(parent *os.File, name string, flags uint64, mode uint64) (*os.File, error) {
	if parent == nil {
		return nil, errMeasuredBundle
	}
	fd, err := unix.Openat2(int(parent.Fd()), name, &unix.OpenHow{Flags: flags | unix.O_CLOEXEC, Mode: mode,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "owned-measured-bundle-object"), nil
}

func openMeasuredBundleJournal(parent, state *os.File, cgroups *np.JobCgroupJournal) (*measuredBundleJournal, error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || cgroups == nil || !persistentBundleFile(parent, true, 0711) || !persistentBundleFile(state, true, 0700) {
		return nil, errMeasuredBundle
	}
	j := &measuredBundleJournal{cgroups: cgroups, active: map[string]*measuredBundle{}}
	var err error
	j.parent, err = openBundleAt(parent, ".", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, errMeasuredBundle
	}
	j.state, err = openBundleAt(state, ".", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		j.parent.Close()
		return nil, errMeasuredBundle
	}
	fail := func() (*measuredBundleJournal, error) {
		if j.lock != nil {
			j.lock.Close()
		}
		j.state.Close()
		j.parent.Close()
		return nil, errMeasuredBundle
	}
	j.lock, err = openBundleAt(j.state, ".lock", unix.O_RDWR|unix.O_CREAT, 0600)
	if err != nil || !persistentBundleFile(j.lock, false, 0600) || unix.Flock(int(j.lock.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil || j.lock.Sync() != nil || j.state.Sync() != nil {
		return fail()
	}
	var st unix.Stat_t
	if unix.Fstat(int(j.parent.Fd()), &st) != nil {
		return fail()
	}
	j.parentDev, j.parentIno = uint64(st.Dev), st.Ino
	return j, nil
}

func decodeMeasuredBundleRecord(raw []byte, name string, owned bool) (measuredBundleRecord, error) {
	var r measuredBundleRecord
	if len(raw) > 4096 || json.Unmarshal(raw, &r) != nil || r.Version != 1 || r.ParentDev == 0 || r.ParentIno == 0 || len(r.Policy) != 64 || strings.Trim(r.Policy, "0123456789abcdef") != "" {
		return r, errMeasuredBundle
	}
	for _, id := range []string{r.Job, r.Lease, r.Execution, r.Attempt} {
		if !measuredBundleID.MatchString(id) || id == "00000000-0000-0000-0000-000000000000" {
			return r, errMeasuredBundle
		}
	}
	suffix := ".intent.json"
	if owned {
		suffix = ".owned.json"
	}
	if name != r.Job+suffix || (owned && (r.BundleDev == 0 || r.BundleIno == 0)) || (!owned && (r.BundleDev != 0 || r.BundleIno != 0)) {
		return r, errMeasuredBundle
	}
	canonical, err := json.Marshal(r)
	if err != nil || !bytes.Equal(raw, append(canonical, '\n')) {
		return r, errMeasuredBundle
	}
	return r, nil
}

func (j *measuredBundleJournal) readRecord(name string, owned bool) (measuredBundleRecord, error) {
	var empty measuredBundleRecord
	f, err := openBundleAt(j.state, name, unix.O_RDONLY, 0)
	if err != nil {
		return empty, errMeasuredBundle
	}
	defer f.Close()
	if !persistentBundleFile(f, false, 0600) {
		return empty, errMeasuredBundle
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return empty, errMeasuredBundle
	}
	return decodeMeasuredBundleRecord(raw, name, owned)
}

func (j *measuredBundleJournal) writeRecord(r measuredBundleRecord, owned bool) error {
	suffix := ".intent.json"
	if owned {
		suffix = ".owned.json"
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return errMeasuredBundle
	}
	raw = append(raw, '\n')
	if _, err := decodeMeasuredBundleRecord(raw, r.Job+suffix, owned); err != nil {
		return err
	}
	f, err := openBundleAt(j.state, r.Job+suffix, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0600)
	if err != nil {
		return errMeasuredBundle
	}
	n, werr := f.Write(raw)
	serr, cerr := f.Sync(), f.Close()
	direrr := j.state.Sync()
	if n != len(raw) || werr != nil || serr != nil || cerr != nil || direrr != nil {
		return errMeasuredBundle
	}
	return nil
}

func (j *measuredBundleJournal) retire(r measuredBundleRecord) error {
	for _, suffix := range []string{".owned.json", ".intent.json"} {
		err := unix.Unlinkat(int(j.state.Fd()), r.Job+suffix, 0)
		if err != nil && err != unix.ENOENT {
			return errMeasuredBundle
		}
		if j.state.Sync() != nil {
			return errMeasuredBundle
		}
	}
	return nil
}

func (j *measuredBundleJournal) create(job *p.JobSpecification) (*measuredBundle, error) {
	if j == nil || job == nil {
		return nil, errMeasuredBundle
	}
	job = proto.Clone(job).(*p.JobSpecification)
	if _, err := np.NewAuthority(job); err != nil {
		return nil, errMeasuredBundle
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || !j.ready || len(j.active) >= 128 {
		return nil, errMeasuredBundle
	}
	r := measuredBundleRecord{Version: 1, Job: job.Lease.JobId, Lease: job.Lease.LeaseId, Execution: job.Lease.ExecutionId, Attempt: job.Attempt.AttemptId,
		Policy: hex.EncodeToString(job.Hashes.Policy.Value), ParentDev: j.parentDev, ParentIno: j.parentIno}
	if _, ok := j.active[r.Job]; ok {
		return nil, errMeasuredBundle
	}
	var existing unix.Stat_t
	if err := unix.Fstatat(int(j.parent.Fd()), r.Job, &existing, unix.AT_SYMLINK_NOFOLLOW); err != unix.ENOENT {
		return nil, errMeasuredBundle
	}
	j.ready = false // every partial creation must be recovered before new admission
	if j.writeRecord(r, false) != nil {
		return nil, errMeasuredBundle
	}
	if unix.Mkdirat(int(j.parent.Fd()), r.Job, 0700) != nil || j.parent.Sync() != nil {
		return nil, errMeasuredBundle
	}
	dir, err := openBundleAt(j.parent, r.Job, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, errMeasuredBundle
	}
	var st unix.Stat_t
	if !persistentBundleFile(dir, true, 0700) || unix.Fstat(int(dir.Fd()), &st) != nil {
		dir.Close()
		return nil, errMeasuredBundle
	}
	r.BundleDev, r.BundleIno = uint64(st.Dev), st.Ino
	if j.writeRecord(r, true) != nil {
		dir.Close()
		return nil, errMeasuredBundle
	}
	b := &measuredBundle{owner: j, record: r, directory: dir}
	j.active[r.Job] = b
	b.scope, err = j.cgroups.Create(job)
	if err != nil {
		return b, errMeasuredBundle
	}
	j.ready = true
	return b, nil
}

func (j *measuredBundleJournal) cleanup(ctx context.Context, b *measuredBundle) error {
	if j == nil || ctx == nil || b == nil {
		return errMeasuredBundle
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if b.owner != j {
		return errMeasuredBundle
	}
	if b.retired {
		return nil
	}
	if j.closed || j.active[b.record.Job] != b {
		return errMeasuredBundle
	}
	if b.scope != nil && j.cgroups.Cleanup(ctx, b.scope) != nil {
		j.ready = false
		return errMeasuredBundle
	}
	if err := j.removeDirectory(ctx, b.record, true); err != nil {
		j.ready = false
		return err
	}
	if j.retire(b.record) != nil {
		j.ready = false
		return errMeasuredBundle
	}
	closeErr := b.directory.Close()
	b.directory = nil
	b.retired = true
	delete(j.active, b.record.Job)
	if closeErr != nil {
		j.ready = false
		return errMeasuredBundle
	}
	return nil
}

func (j *measuredBundleJournal) check(b *measuredBundle, job *p.JobSpecification) error {
	if j == nil || b == nil || job == nil {
		return errMeasuredBundle
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.checkLocked(b, job)
}

func (j *measuredBundleJournal) checkLocked(b *measuredBundle, job *p.JobSpecification) error {
	if j.closed || !j.ready || b.owner != j || b.retired || j.active[b.record.Job] != b || b.scope == nil || job.GetLease().GetJobId() != b.record.Job || job.GetLease().GetLeaseId() != b.record.Lease || job.GetLease().GetExecutionId() != b.record.Execution || job.GetAttempt().GetAttemptId() != b.record.Attempt || hex.EncodeToString(job.GetHashes().GetPolicy().GetValue()) != b.record.Policy {
		return errMeasuredBundle
	}
	if j.cgroups.CheckScope(b.scope) != nil {
		return errMeasuredBundle
	}
	owned, err := j.readRecord(b.record.Job+".owned.json", true)
	if err != nil || owned != b.record {
		j.ready = false
		return errMeasuredBundle
	}
	expected := b.record
	expected.BundleDev, expected.BundleIno = 0, 0
	intent, err := j.readRecord(b.record.Job+".intent.json", false)
	if err != nil || intent != expected {
		j.ready = false
		return errMeasuredBundle
	}
	var actual, retained unix.Stat_t
	if unix.Fstat(int(b.directory.Fd()), &retained) != nil || unix.Fstatat(int(j.parent.Fd()), b.record.Job, &actual, unix.AT_SYMLINK_NOFOLLOW) != nil || actual.Mode&unix.S_IFMT != unix.S_IFDIR || uint64(actual.Dev) != b.record.BundleDev || actual.Ino != b.record.BundleIno || retained.Dev != actual.Dev || retained.Ino != actual.Ino {
		j.ready = false
		return errMeasuredBundle
	}
	return nil
}

func (j *measuredBundleJournal) removeDirectory(ctx context.Context, r measuredBundleRecord, owned bool) error {
	if r.ParentDev != j.parentDev || r.ParentIno != j.parentIno {
		return errMeasuredBundle
	}
	f, err := openBundleAt(j.parent, r.Job, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err == unix.ENOENT {
		return nil
	}
	if err != nil {
		return errMeasuredBundle
	}
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil {
		return errMeasuredBundle
	}
	if owned {
		if uint64(st.Dev) != r.BundleDev || st.Ino != r.BundleIno {
			return errMeasuredBundle
		}
		remaining := 4096
		if removeMeasuredBundleContents(ctx, f, &remaining, 0) != nil {
			return errMeasuredBundle
		}
	} else {
		if !persistentBundleFile(f, true, 0700) {
			return errMeasuredBundle
		}
		entries, err := f.ReadDir(1)
		if err != io.EOF || len(entries) != 0 {
			return errMeasuredBundle
		}
	}
	var current unix.Stat_t
	if unix.Fstatat(int(j.parent.Fd()), r.Job, &current, unix.AT_SYMLINK_NOFOLLOW) != nil || current.Dev != st.Dev || current.Ino != st.Ino || current.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errMeasuredBundle
	}
	if unix.Unlinkat(int(j.parent.Fd()), r.Job, unix.AT_REMOVEDIR) != nil || j.parent.Sync() != nil {
		return errMeasuredBundle
	}
	return nil
}

func (j *measuredBundleJournal) recover(ctx context.Context) error {
	if j == nil || ctx == nil || ctx.Err() != nil {
		return errMeasuredBundle
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || len(j.active) != 0 {
		return errMeasuredBundle
	}
	j.ready = false
	// Whole-scope recovery precedes all filesystem deletion. Cgroup records may
	// already have retired before a crash; the independent bundle records remain.
	if _, err := j.cgroups.Recover(ctx); err != nil {
		return errMeasuredBundle
	}
	view, err := openBundleAt(j.state, ".", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return errMeasuredBundle
	}
	entries, err := view.ReadDir(258)
	view.Close()
	if (err != nil && err != io.EOF) || len(entries) > 257 {
		return errMeasuredBundle
	}
	intents, owned := map[string]measuredBundleRecord{}, map[string]measuredBundleRecord{}
	for _, entry := range entries {
		if entry.Name() == ".lock" {
			continue
		}
		isOwned := strings.HasSuffix(entry.Name(), ".owned.json")
		r, err := j.readRecord(entry.Name(), isOwned)
		if err != nil {
			return errMeasuredBundle
		}
		if isOwned {
			owned[r.Job] = r
		} else {
			intents[r.Job] = r
		}
	}
	if len(intents) > 128 {
		return errMeasuredBundle
	}
	for id, r := range owned {
		r.BundleDev, r.BundleIno = 0, 0
		if intents[id] != r {
			return errMeasuredBundle
		}
	}
	view, err = openBundleAt(j.parent, ".", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return errMeasuredBundle
	}
	children, err := view.ReadDir(129)
	view.Close()
	if (err != nil && err != io.EOF) || len(children) > 128 {
		return errMeasuredBundle
	}
	for _, child := range children {
		if _, ok := intents[child.Name()]; !ok || !child.IsDir() {
			return errMeasuredBundle
		}
	}
	ids := make([]string, 0, len(intents))
	for id := range intents {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if ctx.Err() != nil {
			return errMeasuredBundle
		}
		r, isOwned := owned[id]
		if !isOwned {
			r = intents[id]
		}
		if j.removeDirectory(ctx, r, isOwned) != nil || j.retire(r) != nil {
			return errMeasuredBundle
		}
	}
	j.ready = true
	return nil
}

func (j *measuredBundleJournal) close() error {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return nil
	}
	if len(j.active) != 0 {
		return errMeasuredBundle
	}
	j.closed = true
	j.ready = false
	err1, err2, err3 := j.lock.Close(), j.state.Close(), j.parent.Close()
	if err1 != nil || err2 != nil || err3 != nil {
		return errMeasuredBundle
	}
	return nil
}

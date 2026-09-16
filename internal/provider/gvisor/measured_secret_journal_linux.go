//go:build linux

package gvisor

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	"golang.org/x/sys/unix"
)

func validMeasuredSecretRecord(r measuredBundleRecord, owned bool) bool {
	if r.SecretBoot == "" {
		return r.SecretParentDev == 0 && r.SecretParentIno == 0 && r.SecretDev == 0 && r.SecretIno == 0
	}
	if !measuredBundleID.MatchString(r.SecretBoot) || r.SecretBoot == "00000000-0000-0000-0000-000000000000" || r.SecretParentDev == 0 || r.SecretParentIno == 0 {
		return false
	}
	if owned {
		return r.SecretDev != 0 && r.SecretIno != 0
	}
	return r.SecretDev == 0 && r.SecretIno == 0
}

// OpenMeasuredBundleJournalWithSecrets retains a separately provisioned tmpfs
// parent. The persistent bundle journal records intent before any secret child
// is created. Recovery drains the whole cgroup journal before touching secrets.
// This constructor neither supplies values nor enables secret-bearing jobs.
func OpenMeasuredBundleJournalWithSecrets(parent, state, secretParent *os.File, cgroups *np.JobCgroupJournal) (*MeasuredBundleJournal, error) {
	if !measuredSecretParent(secretParent) {
		return nil, errMeasuredBundle
	}
	j, err := openMeasuredBundleJournal(parent, state, cgroups)
	if err != nil {
		return nil, err
	}
	fail := func() (*MeasuredBundleJournal, error) { _ = j.close(); return nil, errMeasuredBundle }
	j.secretParent, err = openBundleAt(secretParent, ".", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return fail()
	}
	var st unix.Stat_t
	if !measuredSecretParent(j.secretParent) || unix.Fstat(int(j.secretParent.Fd()), &st) != nil {
		return fail()
	}
	j.secretParentDev, j.secretParentIno = uint64(st.Dev), st.Ino
	j.secretPath, err = os.Readlink(fmt.Sprintf("/proc/self/fd/%d", j.secretParent.Fd()))
	if err != nil || !j.secretPathValid() {
		return fail()
	}
	f, err := os.OpenFile("/proc/sys/kernel/random/boot_id", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fail()
	}
	raw, err := io.ReadAll(io.LimitReader(f, 38))
	closeErr := f.Close()
	j.secretBoot = strings.TrimSuffix(string(raw), "\n")
	if err != nil || closeErr != nil || len(raw) != 37 || !measuredBundleID.MatchString(j.secretBoot) {
		return fail()
	}
	return j, nil
}

func (j *measuredBundleJournal) secretPathValid() bool {
	if !filepath.IsAbs(j.secretPath) || filepath.Clean(j.secretPath) != j.secretPath || j.secretPath == "/" || len(j.secretPath) > 4096 || strings.ContainsAny(j.secretPath, "\x00\r\n") {
		return false
	}
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer func() { _ = unix.Close(fd) }()
	// Every ancestor is root-owned and non-writable, except root-owned sticky
	// directories such as /dev/shm. Their root-owned children cannot be renamed
	// by the worker between validation and the gofer opening the mount source.
	for _, component := range strings.Split(strings.TrimPrefix(j.secretPath, "/"), "/") {
		var parent unix.Stat_t
		if unix.Fstat(fd, &parent) != nil || parent.Uid != 0 || parent.Gid != 0 || (parent.Mode&0022 != 0 && parent.Mode&unix.S_ISVTX == 0) {
			return false
		}
		next, err := unix.Openat2(fd, component, &unix.OpenHow{Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
		if err != nil {
			return false
		}
		_ = unix.Close(fd)
		fd = next
	}
	var st unix.Stat_t
	return unix.Fstat(fd, &st) == nil && uint64(st.Dev) == j.secretParentDev && st.Ino == j.secretParentIno && st.Uid == 0 && st.Gid == 0 && st.Mode == unix.S_IFDIR|0711
}

func measuredSecretParent(f *os.File) bool {
	if f == nil {
		return false
	}
	var st unix.Stat_t
	var fs unix.Statfs_t
	return unix.Fstat(int(f.Fd()), &st) == nil && st.Mode == unix.S_IFDIR|0711 && st.Uid == 0 && st.Gid == 0 && st.Nlink != 0 && unix.Fstatfs(int(f.Fd()), &fs) == nil && fs.Type == unix.TMPFS_MAGIC
}

func (j *measuredBundleJournal) secretParentValid() bool {
	if !measuredSecretParent(j.secretParent) || !j.secretPathValid() {
		return false
	}
	var st unix.Stat_t
	return unix.Fstat(int(j.secretParent.Fd()), &st) == nil && uint64(st.Dev) == j.secretParentDev && st.Ino == j.secretParentIno
}

func (j *measuredBundleJournal) createSecretDirectory(r *measuredBundleRecord) error {
	if r.SecretBoot == "" {
		return nil
	}
	if !j.secretParentValid() || unix.Mkdirat(int(j.secretParent.Fd()), r.Job, 0700) != nil {
		return errMeasuredBundle
	}
	f, err := openBundleAt(j.secretParent, r.Job, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return errMeasuredBundle
	}
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil || st.Mode != unix.S_IFDIR|0700 || st.Uid != 0 || st.Gid != 0 {
		return errMeasuredBundle
	}
	r.SecretDev, r.SecretIno = uint64(st.Dev), st.Ino
	return nil
}

func (j *measuredBundleJournal) checkSecretDirectory(r measuredBundleRecord) error {
	if r.SecretBoot == "" {
		return nil
	}
	if !j.secretParentValid() || r.SecretBoot != j.secretBoot || r.SecretParentDev != j.secretParentDev || r.SecretParentIno != j.secretParentIno {
		return errMeasuredBundle
	}
	f, err := openBundleAt(j.secretParent, r.Job, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return errMeasuredBundle
	}
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil || uint64(st.Dev) != r.SecretDev || st.Ino != r.SecretIno || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0022 != 0 {
		return errMeasuredBundle
	}
	return nil
}

func (j *measuredBundleJournal) checkSecretChildren(intents map[string]measuredBundleRecord) error {
	if j.secretParent == nil {
		for _, r := range intents {
			if r.SecretBoot != "" {
				return errMeasuredBundle
			}
		}
		return nil
	}
	if !j.secretParentValid() {
		return errMeasuredBundle
	}
	f, err := openBundleAt(j.secretParent, ".", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return errMeasuredBundle
	}
	defer f.Close()
	entries, err := f.ReadDir(129)
	if (err != nil && err != io.EOF) || len(entries) > 128 {
		return errMeasuredBundle
	}
	for _, entry := range entries {
		r, ok := intents[entry.Name()]
		if !ok || r.SecretBoot == "" || !entry.IsDir() {
			return errMeasuredBundle
		}
	}
	return nil
}

// Called only after whole-scope retirement. A previous boot may retire records
// only if its tmpfs child is absent; it never authorizes deleting a current one.
func (j *measuredBundleJournal) removeSecretDirectory(ctx context.Context, r measuredBundleRecord, owned bool) error {
	if r.SecretBoot == "" {
		return nil
	}
	if ctx == nil || ctx.Err() != nil || !j.secretParentValid() {
		return errMeasuredBundle
	}
	if r.SecretBoot == j.secretBoot && (r.SecretParentDev != j.secretParentDev || r.SecretParentIno != j.secretParentIno) {
		return errMeasuredBundle
	}
	f, err := openBundleAt(j.secretParent, r.Job, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err == unix.ENOENT {
		return nil
	}
	if err != nil {
		return errMeasuredBundle
	}
	defer f.Close()
	var st unix.Stat_t
	if r.SecretBoot != j.secretBoot || unix.Fstat(int(f.Fd()), &st) != nil || st.Uid != 0 {
		return errMeasuredBundle
	}
	if owned {
		if uint64(st.Dev) != r.SecretDev || st.Ino != r.SecretIno {
			return errMeasuredBundle
		}
		remaining := 65
		if removeMeasuredBundleContents(ctx, f, &remaining, 0) != nil {
			return errMeasuredBundle
		}
	} else {
		if st.Mode != unix.S_IFDIR|0700 || st.Gid != 0 {
			return errMeasuredBundle
		}
		entries, readErr := f.ReadDir(1)
		if readErr != io.EOF || len(entries) != 0 {
			return errMeasuredBundle
		}
	}
	var current unix.Stat_t
	if unix.Fstatat(int(j.secretParent.Fd()), r.Job, &current, unix.AT_SYMLINK_NOFOLLOW) != nil || current.Dev != st.Dev || current.Ino != st.Ino || current.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errMeasuredBundle
	}
	if unix.Unlinkat(int(j.secretParent.Fd()), r.Job, unix.AT_REMOVEDIR) != nil {
		return errMeasuredBundle
	}
	return nil
}

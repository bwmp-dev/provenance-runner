//go:build linux

package networkpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// HostUplinkJournal is a single-uplink ownership boundary, not a global job or
// identity allocator. Its persistent intent precedes every host link mutation.
// Recovery never adopts or deletes a surviving host interface.
type HostUplinkJournal struct {
	mu                   sync.Mutex
	state, lock, network *os.File
	tools                RouteTools
	boot                 string
	dev, ino             uint64
	active               *HostUplink
	ready, closed        bool
}

type uplinkRecord struct {
	Version       int    `json:"version"`
	Token         string `json:"token"`
	Boot          string `json:"boot"`
	NetworkDev    uint64 `json:"networkDev"`
	NetworkIno    uint64 `json:"networkIno"`
	Job           string `json:"job"`
	Lease         string `json:"lease"`
	Execution     string `json:"execution"`
	Attempt       string `json:"attempt"`
	Candidate     string `json:"candidate"`
	Matrix        string `json:"matrix"`
	AttemptNumber uint32 `json:"attemptNumber"`
	Policy        string `json:"policy"`
}

func (r uplinkRecord) hostName() string    { return "ph" + r.Token[:13] }
func (r uplinkRecord) routerStage() string { return "pr" + r.Token[:13] }
func (r uplinkRecord) alias() string       { return "provenance:" + r.Job + ":" + r.Token }

func validUplinkRecord(r uplinkRecord) bool {
	if r.Version != 1 || !validJournalToken(r.Token) || !validJournalToken(r.Policy) || !validAuthorityID(r.Boot) || r.NetworkDev == 0 || r.NetworkIno == 0 || r.AttemptNumber < 1 || r.AttemptNumber > 3 {
		return false
	}
	for _, id := range []string{r.Job, r.Lease, r.Execution, r.Attempt, r.Candidate, r.Matrix} {
		if !validAuthorityID(id) {
			return false
		}
	}
	return true
}

func decodeUplinkRecord(raw []byte, name string) (uplinkRecord, error) {
	var r uplinkRecord
	if len(raw) > 4096 || json.Unmarshal(raw, &r) != nil || !validUplinkRecord(r) || name != r.Token+".json" {
		return r, ErrNamespace
	}
	canonical, err := json.Marshal(r)
	if err != nil || !bytes.Equal(raw, append(canonical, '\n')) {
		return r, ErrNamespace
	}
	return r, nil
}

// OpenHostUplinkJournal retains the controller's current network namespace. No
// workload-selected namespace or host path is accepted. The state directory is
// a trusted, root-private persistent descriptor. Recover is mandatory first.
func OpenHostUplinkJournal(state *os.File, selected RouteTools) (*HostUplinkJournal, error) {
	groups, err := os.Getgroups()
	if os.Getuid() != 0 || os.Geteuid() != 0 || err != nil || len(groups) != 0 || !protectedJournalFile(state, true) {
		return nil, ErrNamespace
	}
	j := &HostUplinkJournal{}
	fail := func() (*HostUplinkJournal, error) { _ = j.Close(); return nil, ErrNamespace }
	fd, err := unix.FcntlInt(state.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return fail()
	}
	j.state = os.NewFile(uintptr(fd), "host-uplink-state")
	j.lock, err = journalOpenAt(j.state, ".lock", unix.O_RDWR|unix.O_CREAT, 0600)
	if err != nil || unix.Flock(int(j.lock.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		return fail()
	}
	j.network, err = os.Open("/proc/self/ns/net")
	if err != nil {
		return fail()
	}
	var st unix.Stat_t
	var fs unix.Statfs_t
	kind, err := unix.IoctlRetInt(int(j.network.Fd()), unix.NS_GET_NSTYPE)
	if err != nil || kind != unix.CLONE_NEWNET || unix.Fstat(int(j.network.Fd()), &st) != nil || unix.Fstatfs(int(j.network.Fd()), &fs) != nil || fs.Type != unix.NSFS_MAGIC {
		return fail()
	}
	j.dev, j.ino = uint64(st.Dev), st.Ino
	j.boot, err = kernelBootID()
	if err != nil {
		return fail()
	}
	for _, item := range []struct {
		from ProtectedRouteTool
		to   *ProtectedRouteTool
	}{{selected.NSenter, &j.tools.NSenter}, {selected.NFT, &j.tools.NFT}, {selected.IP, &j.tools.IP}} {
		if !validRouteTool(item.from) {
			return fail()
		}
		fd, err := unix.FcntlInt(item.from.File.Fd(), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			return fail()
		}
		*item.to = ProtectedRouteTool{File: os.NewFile(uintptr(fd), "host-uplink-tool"), SHA256: item.from.SHA256}
		if !validRouteTool(*item.to) {
			return fail()
		}
	}
	return j, nil
}

func (j *HostUplinkJournal) execute(ctx context.Context, args ...string) ([]byte, error) {
	return executeRetainedTool(ctx, j.network, j.tools.NSenter, j.tools.IP, nil, "", args...)
}

func (j *HostUplinkJournal) readRecord(name string) (uplinkRecord, error) {
	var record uplinkRecord
	f, err := journalOpenAt(j.state, name, unix.O_RDONLY, 0)
	if err != nil {
		return record, ErrNamespace
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return record, ErrNamespace
	}
	return decodeUplinkRecord(raw, name)
}

func (j *HostUplinkJournal) writeRecord(r uplinkRecord) error {
	if !validUplinkRecord(r) {
		return ErrNamespace
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return ErrNamespace
	}
	raw = append(raw, '\n')
	f, err := journalOpenAt(j.state, r.Token+".json", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0600)
	if err != nil {
		return ErrNamespace
	}
	n, werr := f.Write(raw)
	syncErr, closeErr := f.Sync(), f.Close()
	if n != len(raw) || werr != nil || syncErr != nil || closeErr != nil || j.state.Sync() != nil {
		return ErrNamespace
	}
	return nil
}

func (j *HostUplinkJournal) retireRecord(r uplinkRecord) error {
	actual, err := j.readRecord(r.Token + ".json")
	if err != nil || actual != r {
		return ErrNamespace
	}
	if unix.Unlinkat(int(j.state.Fd()), r.Token+".json", 0) != nil || j.state.Sync() != nil {
		return ErrNamespace
	}
	return nil
}

// Recover must follow drainage of the process journals. It waits at most five
// seconds for kernel removal of an owned peer, and refuses foreign identities.
// It never deletes a host interface, recreates a router, or restores permission.
func (j *HostUplinkJournal) Recover(ctx context.Context) error {
	if j == nil || ctx == nil {
		return ErrNamespace
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.active != nil || !protectedJournalFile(j.state, true) {
		return ErrNamespace
	}
	j.ready = false
	dir, err := os.Open("/proc/self/fd/" + strconv.Itoa(int(j.state.Fd())))
	if err != nil {
		return ErrNamespace
	}
	entries, err := dir.ReadDir(4)
	dir.Close()
	if (err != nil && err != io.EOF) || len(entries) > 2 {
		return ErrNamespace
	}
	for _, entry := range entries {
		if entry.Name() == ".lock" {
			continue
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			return ErrNamespace
		}
		r, err := j.readRecord(entry.Name())
		if err != nil || (r.Boot == j.boot && (r.NetworkDev != j.dev || r.NetworkIno != j.ino)) {
			return ErrNamespace
		}
		deadline, cancel := context.WithTimeout(ctx, 5*time.Second)
		for {
			links, err := j.inventory(deadline)
			if err != nil {
				cancel()
				return err
			}
			present := false
			for _, link := range links {
				if link.Name != r.hostName() {
					continue
				}
				if r.Boot != j.boot || link.Alias != r.alias()+":host" || link.Info.Kind != "veth" {
					cancel()
					return ErrNamespace
				}
				present = true
			}
			if !present {
				break
			}
			select {
			case <-deadline.Done():
				cancel()
				return ErrNamespace
			case <-time.After(25 * time.Millisecond):
			}
		}
		cancel()
		if err := j.retireRecord(r); err != nil {
			return err
		}
	}
	if ctx.Err() != nil || j.prefixesAvailable(ctx) != nil {
		return ErrNamespace
	}
	j.ready = true
	return nil
}

func (j *HostUplinkJournal) Close() error {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return nil
	}
	if j.active != nil {
		return ErrNamespace
	}
	j.closed = true
	j.ready = false
	var errs []error
	for _, file := range []*os.File{j.tools.NSenter.File, j.tools.NFT.File, j.tools.IP.File, j.network, j.lock, j.state} {
		if file != nil {
			errs = append(errs, file.Close())
		}
	}
	return errors.Join(errs...)
}

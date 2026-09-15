package paper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/bwmp-dev/provenance-runner/internal/localjob"
	"github.com/bwmp-dev/provenance-runner/internal/pluginname"
	"github.com/bwmp-dev/provenance-runner/internal/workspace"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
)

const maximumMeasuredGuestConfiguration = 64 << 10

type measuredGuestConfiguration struct {
	Version            int                     `json:"version"`
	JobID              string                  `json:"jobId"`
	Inputs             []MeasuredInputIdentity `json:"inputs"`
	Layout             MeasuredRuntimeLayout   `json:"layout"`
	MemoryBytes        uint64                  `json:"memoryBytes"`
	DiskBytes          uint64                  `json:"diskBytes"`
	MaximumOutputBytes int64                   `json:"maximumOutputBytes"`
}

// GuestConfiguration is a non-secret bootstrap description for a measured guest
// helper. It is bound to the same complete job as the signed input plan and
// supplies no arbitrary command, host mount or download location.
func (m *MeasuredInputPlan) GuestConfiguration(job *p.JobSpecification) ([]byte, error) {
	if !m.Matches(job) {
		return nil, ErrMeasuredInputPlan
	}
	c := measuredGuestConfiguration{Version: 1, JobID: job.Lease.JobId, Inputs: m.Inputs(), Layout: m.RuntimeLayout(), MemoryBytes: job.EffectivePolicy.Resources.MemoryBytes, DiskBytes: job.EffectivePolicy.Resources.DiskBytes}
	normalized, _, err := decodeNormalizedConfiguration(job.NormalizedConfigurationJson)
	if err != nil {
		return nil, ErrMeasuredInputPlan
	}
	c.MaximumOutputBytes = normalized.Resources.LogBytes
	if !validMeasuredGuestConfiguration(c) {
		return nil, ErrMeasuredInputPlan
	}
	raw, err := json.Marshal(c)
	if err != nil || len(raw) > maximumMeasuredGuestConfiguration {
		return nil, ErrMeasuredInputPlan
	}
	return raw, nil
}

func validMeasuredGuestConfiguration(c measuredGuestConfiguration) bool {
	if c.MaximumOutputBytes < 1 || c.MaximumOutputBytes > localjob.MaximumOutputBytes {
		return false
	}
	if c.Version != 1 || len(c.JobID) != 36 || strings.ContainsAny(c.JobID, "/\\\x00") || len(c.Inputs) < 6 || len(c.Inputs) > 256 || c.MemoryBytes < 16<<20 || c.MemoryBytes > 64<<30 || c.DiskBytes < 1<<20 || c.DiskBytes > 64<<30 || c.Layout.JavaMaximumExpandedBytes == 0 || c.Layout.JavaMaximumExpandedBytes > 1<<30 || c.Layout.PreparedMaximumExpandedBytes == 0 || c.Layout.PreparedMaximumExpandedBytes > 1<<30 {
		return false
	}
	if _, err := cleanGuestArchiveRoot(c.Layout.JavaArchiveRoot); err != nil {
		return false
	}
	seed := c.Layout.JavaMaximumExpandedBytes + c.Layout.PreparedMaximumExpandedBytes + 64<<10
	for i, input := range c.Inputs {
		name := ""
		switch i {
		case 0:
			name = "java.tar.gz"
		case 1:
			name = "paper.jar"
		case 2:
			name = "provenance-probe.jar"
		case 3:
			name = "prepared-runtime.tar.gz"
		case 4:
			name = "target.jar"
		default:
			if i == len(c.Inputs)-1 {
				name = "provenance-test-plan.json"
			} else {
				name = fmt.Sprintf("dependency-%03d.jar", i-5)
			}
		}
		if input.Name != name || input.SizeBytes == 0 || input.SizeBytes > 64<<30 || input.SHA256 == ([32]byte{}) {
			return false
		}
		if i == len(c.Inputs)-1 && input.SizeBytes > maximumProbePlanBytes {
			return false
		}
		if i != 0 && i != 3 {
			if input.SizeBytes > 64<<30-seed {
				return false
			}
			seed += input.SizeBytes
		}
	}
	return seed <= (c.DiskBytes+1)/2
}

func cleanGuestArchiveRoot(root string) (string, error) {
	if root == "" || len(root) > 256 || filepath.IsAbs(root) || filepath.Clean(root) != root || root == "." || root == ".." || strings.HasPrefix(root, ".."+string(filepath.Separator)) || strings.ContainsAny(root, "\\\x00") {
		return "", ErrMeasuredInputPlan
	}
	return root, nil
}

type preparedMeasuredGuest struct {
	workspace              *workspace.Workspace
	command, cwd           string
	arguments, environment []string
	maximumOutput          int64
}

// prepareMeasuredGuest performs no execution. Its future entry point must supply
// fixed /inputs and /workspace inside the measured guest, never RPC path fields.
// The fresh workspace is exclusively owned until Java is started.
func prepareMeasuredGuest(ctx context.Context, raw []byte, inputsRoot, workspaceRoot string) (owned *preparedMeasuredGuest, result error) {
	if ctx == nil || ctx.Err() != nil || len(raw) == 0 || len(raw) > maximumMeasuredGuestConfiguration {
		return nil, ErrMeasuredInputPlan
	}
	var c measuredGuestConfiguration
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF || !validMeasuredGuestConfiguration(c) {
		return nil, ErrMeasuredInputPlan
	}
	canonical, err := json.Marshal(c)
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, ErrMeasuredInputPlan
	}
	// Retain and verify all fixed inputs before creating a mutable guest tree.
	files := make([]*os.File, 0, len(c.Inputs))
	defer func() {
		for _, file := range files {
			_ = file.Close()
		}
	}()
	for _, input := range c.Inputs {
		path := filepath.Join(inputsRoot, input.Name)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0222 != 0 || info.Size() < 0 || uint64(info.Size()) != input.SizeBytes {
			return nil, ErrMeasuredInputPlan
		}
		file, err := os.Open(path)
		if err != nil {
			return nil, ErrMeasuredInputPlan
		}
		files = append(files, file)
		retained, err := file.Stat()
		if err != nil || !os.SameFile(info, retained) {
			return nil, ErrMeasuredInputPlan
		}
		h := sha256.New()
		n, err := io.Copy(h, &measuredGuestReader{ctx: ctx, reader: io.NewSectionReader(file, 0, int64(input.SizeBytes)+1)})
		if err != nil || uint64(n) != input.SizeBytes || !bytes.Equal(h.Sum(nil), input.SHA256[:]) {
			return nil, ErrMeasuredInputPlan
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	manager, err := workspace.NewManager(workspaceRoot)
	if err != nil {
		return nil, err
	}
	w, err := manager.Create(ctx, c.JobID)
	if err != nil {
		return nil, err
	}
	owned = &preparedMeasuredGuest{workspace: w, maximumOutput: c.MaximumOutputBytes}
	defer func() {
		if result != nil {
			result = errors.Join(result, w.Cleanup(context.Background()))
			owned = nil
		}
	}()
	java, err := w.ExtractTarGzipReaderBounded(ctx, "runtime", io.NewSectionReader(files[0], 0, int64(c.Inputs[0].SizeBytes)), int64(c.Layout.JavaMaximumExpandedBytes))
	if err != nil {
		return nil, err
	}
	server, err := w.ExtractTarGzipReaderBounded(ctx, "server", io.NewSectionReader(files[3], 0, int64(c.Inputs[3].SizeBytes)), int64(c.Layout.PreparedMaximumExpandedBytes))
	if err != nil {
		return nil, err
	}
	// Mutable Paper state remains confined to this guest-owned server tree.
	entries, err := os.ReadDir(server)
	if err != nil || len(entries) == 0 || len(entries) > len(preparedRuntimeRoots) {
		return nil, ErrMeasuredInputPlan
	}
	for _, entry := range entries {
		allowed := false
		for _, name := range preparedRuntimeRoots {
			allowed = allowed || entry.Name() == name
		}
		if !allowed || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil, ErrMeasuredInputPlan
		}
	}
	if err := filepath.WalkDir(server, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if entry.IsDir() {
			return os.Chmod(path, 0700)
		}
		return os.Chmod(path, 0600)
	}); err != nil {
		return nil, err
	}
	// Prepared caches may not prepopulate the files whose identities are owned
	// separately by the job. WriteFile uses exclusive creation and hash-checked data.
	for i, input := range c.Inputs {
		if i == 0 || i == 3 {
			continue
		}
		name := input.Name
		if i == 2 || i == 4 || (i >= 5 && i < len(c.Inputs)-1) {
			name = "plugins/" + name
		}
		if err := copyMeasuredGuestFile(ctx, files[i], filepath.Join(server, name), input); err != nil {
			return nil, err
		}
	}
	if _, err = w.WriteFile(ctx, "server/eula.txt", []byte("eula=true\n"), 0600); err != nil {
		return nil, err
	}
	if _, err = w.WriteFile(ctx, "server/server.properties", []byte(minimalServerProperties), 0600); err != nil {
		return nil, err
	}
	planBytes, err := os.ReadFile(filepath.Join(server, "provenance-test-plan.json"))
	if err != nil || len(planBytes) > maximumProbePlanBytes {
		return nil, ErrMeasuredInputPlan
	}
	var plan testPlan
	decoder := json.NewDecoder(bytes.NewReader(planBytes))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&plan) != nil || decoder.Decode(new(any)) != io.EOF || !pluginname.ValidPaper(plan.TargetPlugin) || plan.StabilizationMilliseconds < 1000 || plan.StabilizationMilliseconds > 60000 || len(plan.RequiredDependencies) > 250 || validateConsoleTests(plan.Console) != nil {
		return nil, ErrMeasuredInputPlan
	}
	for _, name := range plan.RequiredDependencies {
		if !pluginname.ValidPaper(name) {
			return nil, ErrMeasuredInputPlan
		}
	}
	javaHome := filepath.Join(java, c.Layout.JavaArchiveRoot)
	owned.command = filepath.Join(javaHome, "bin/java")
	info, err := os.Lstat(owned.command)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return nil, ErrMeasuredInputPlan
	}
	owned.cwd = server
	required := append([]string(nil), plan.RequiredDependencies...)
	sort.Strings(required)
	heap := c.MemoryBytes * 3 / 4 / (1 << 20)
	initial := uint64(256)
	if heap < initial {
		initial = heap
	}
	owned.arguments = []string{"-Xms" + strconv.FormatUint(initial, 10) + "M", "-Xmx" + strconv.FormatUint(heap, 10) + "M", "-Dhttp.agent=" + DownloadUserAgent, "-Dprovenance.probe.target=" + plan.TargetPlugin, "-Dprovenance.probe.requiredDependencies=" + strings.Join(required, ","), "-Dprovenance.probe.events=/tmp/provenance-probe-events.ndjson", "-Dprovenance.probe.testPlan=" + filepath.Join(server, "provenance-test-plan.json"), "-Dprovenance.probe.stabilizationMillis=" + strconv.FormatInt(plan.StabilizationMilliseconds, 10), "-Dprovenance.probe.requestShutdown=true", "-jar", filepath.Join(server, "paper.jar"), "nogui"}
	owned.environment = []string{"JAVA_HOME=" + javaHome, "PATH=" + filepath.Join(javaHome, "bin") + ":/usr/bin:/bin", "HOME=" + server, "LANG=C.UTF-8"}
	return owned, nil
}

func copyMeasuredGuestFile(ctx context.Context, source *os.File, path string, input MeasuredInputIdentity) (result error) {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, out.Close()) }()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), &measuredGuestReader{ctx: ctx, reader: io.NewSectionReader(source, 0, int64(input.SizeBytes)+1)})
	if err != nil || uint64(n) != input.SizeBytes || !bytes.Equal(h.Sum(nil), input.SHA256[:]) {
		return ErrMeasuredInputPlan
	}
	return ctx.Err()
}

type measuredGuestReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *measuredGuestReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}

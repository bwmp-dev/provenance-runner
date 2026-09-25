package gvisor

// WP-11C hostile-input boundary tests for the gVisor provider.
//
// These tests exercise the runner-side boundaries that receive hostile
// material: the local job/environment configuration decoder, the guest output
// pipeline (runsc stdout/stderr into the evidence collector and live observer),
// customer plugin JAR bytes placed under the job inputs directory, and
// cross-job input isolation. They use the package's fake runsc command runner,
// never launch a sandbox, and never execute hostile payloads, so they are safe
// in ordinary `go test -race ./...`. The live sandbox counterparts are the
// real-runsc smoke and the Plan 03 hostile matrix; see
// docs/security/hostile-fixture-inventory.md.

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/bwmp-dev/provenance-runner/internal/evidence"
	"github.com/bwmp-dev/provenance-runner/internal/execution"
	"github.com/bwmp-dev/provenance-runner/internal/localjob"
)

// hostileJar is one malformed or hostile plugin archive fixture. Each is
// generated deterministically in memory so no binary blob is committed.
type hostileJar struct {
	name    string
	proves  string
	content []byte
}

func hostileJars(t testing.TB) []hostileJar {
	t.Helper()
	build := func(entries ...zipEntry) []byte {
		var buffer bytes.Buffer
		writer := zip.NewWriter(&buffer)
		for _, entry := range entries {
			header := &zip.FileHeader{Name: entry.name, Method: zip.Deflate}
			if entry.store {
				header.Method = zip.Store
			}
			file, err := writer.CreateHeader(header)
			if err != nil {
				t.Fatalf("create zip entry %q: %v", entry.name, err)
			}
			if entry.repeat > 0 {
				chunk := bytes.Repeat([]byte{entry.fill}, 1<<16)
				for written := 0; written < entry.repeat; written += len(chunk) {
					if _, err := file.Write(chunk[:min(len(chunk), entry.repeat-written)]); err != nil {
						t.Fatal(err)
					}
				}
			} else if _, err := file.Write(entry.data); err != nil {
				t.Fatal(err)
			}
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		return buffer.Bytes()
	}
	pluginYML := zipEntry{name: "plugin.yml", data: []byte("name: Hostile\nversion: 1\nmain: x.Y\n")}
	valid := build(pluginYML, zipEntry{name: "x/Y.class", data: []byte{0xca, 0xfe, 0xba, 0xbe}})
	manifest := bytes.Buffer{}
	manifest.WriteString("Manifest-Version: 1.0\r\n")
	for manifest.Len() < 8<<20 {
		manifest.WriteString("X-Hostile-Attribute: " + strings.Repeat("A", 60) + "\r\n")
	}
	return []hostileJar{
		{name: "zip-bomb.jar", proves: "64 MiB of zeros compressed to a few KiB is never inflated on the host", content: build(pluginYML, zipEntry{name: "bomb.bin", fill: 0, repeat: 64 << 20})},
		{name: "path-traversal.jar", proves: "../, absolute and backslash entry names never materialize outside the job", content: build(pluginYML,
			zipEntry{name: "../../../../tmp/provenance-wp11c-escape", data: []byte("escaped")},
			zipEntry{name: "/etc/provenance-wp11c-escape", data: []byte("escaped")},
			zipEntry{name: `..\..\provenance-wp11c-escape`, data: []byte("escaped")})},
		{name: "duplicate-entries.jar", proves: "duplicate plugin.yml entries are passed through byte-exact for Paper to reject", content: build(pluginYML, zipEntry{name: "plugin.yml", data: []byte("name: Shadow\nversion: 2\nmain: a.B\n")})},
		{name: "huge-manifest.jar", proves: "an 8 MiB META-INF/MANIFEST.MF is never parsed by the runner", content: build(zipEntry{name: "META-INF/MANIFEST.MF", data: manifest.Bytes()}, pluginYML)},
		{name: "not-a-zip.jar", proves: "non-zip bytes are staged as opaque data; Paper classifies the load failure", content: []byte("#!/bin/sh\necho this is not a jar\n\x00\xff\xfe")},
		{name: "truncated.jar", proves: "a truncated central directory is staged byte-exact and never repaired", content: valid[:len(valid)/2]},
		{name: "empty.jar", proves: "zero-length input is data, not an error path that aborts cleanup", content: nil},
	}
}

type zipEntry struct {
	name   string
	data   []byte
	store  bool
	fill   byte
	repeat int
}

// TestHostileJarCorpusIsGenuinelyHostile guards the corpus itself: a fixture
// that silently became benign would make every downstream assertion vacuous.
func TestHostileJarCorpusIsGenuinelyHostile(t *testing.T) {
	jars := map[string][]byte{}
	for _, jar := range hostileJars(t) {
		jars[jar.name] = jar.content
	}
	open := func(name string) *zip.Reader {
		t.Helper()
		reader, err := zip.NewReader(bytes.NewReader(jars[name]), int64(len(jars[name])))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return reader
	}
	bomb := open("zip-bomb.jar")
	var expanded uint64
	for _, file := range bomb.File {
		expanded += file.UncompressedSize64
	}
	if ratio := expanded / uint64(len(jars["zip-bomb.jar"])); ratio < 500 {
		t.Fatalf("zip bomb compression ratio = %d, want >= 500", ratio)
	}
	traversal := 0
	for _, file := range open("path-traversal.jar").File {
		if strings.Contains(file.Name, "..") || strings.HasPrefix(file.Name, "/") {
			traversal++
		}
	}
	if traversal != 3 {
		t.Fatalf("traversal entries = %d", traversal)
	}
	names := map[string]int{}
	for _, file := range open("duplicate-entries.jar").File {
		names[file.Name]++
	}
	if names["plugin.yml"] != 2 {
		t.Fatalf("duplicate entries = %#v", names)
	}
	if manifest := open("huge-manifest.jar").File[0]; manifest.UncompressedSize64 < 8<<20 {
		t.Fatalf("manifest size = %d", manifest.UncompressedSize64)
	}
	for _, name := range []string{"not-a-zip.jar", "truncated.jar", "empty.jar"} {
		if _, err := zip.NewReader(bytes.NewReader(jars[name]), int64(len(jars[name]))); err == nil {
			t.Fatalf("%s unexpectedly parses as a zip archive", name)
		}
	}
}

// TestHostileJarsAreOpaqueReadOnlyInputs proves the runner never inflates,
// rewrites or path-resolves customer archive entries. Every hostile JAR is
// exposed to the guest only through the read-only, noexec, nosuid, nodev
// /inputs bind mount; bytes are unchanged after the full job lifecycle; no
// traversal entry materializes; and the host footprint stays bounded by the
// compressed sizes.
func TestHostileJarsAreOpaqueReadOnlyInputs(t *testing.T) {
	provider, runner, roots := testProvider(t)
	jobInputs := filepath.Join(roots.inputs, "job-1")
	jars := hostileJars(t)
	digests := map[string][32]byte{}
	var compressed int64
	for _, jar := range jars {
		if err := os.WriteFile(filepath.Join(jobInputs, jar.name), jar.content, 0o444); err != nil {
			t.Fatal(err)
		}
		digests[jar.name] = sha256.Sum256(jar.content)
		compressed += int64(len(jar.content))
	}
	var spec ociSpec
	runner.run = func(_ context.Context, invocation command) commandResult {
		if commandVerb(invocation.Args) == "run" {
			spec = readBundleSpec(t, invocation.Args)
		}
		return successResult()
	}
	result := executeGVisorJob(t, provider, mustJSON(t, validConfiguration()), 4096, nil)
	if result.Classification != execution.ClassificationPassed {
		t.Fatalf("classification = %s failure = %#v", result.Classification, result.Failure)
	}
	inputs := findMount(t, spec.Mounts, "/inputs")
	if inputs.Source != jobInputs || !containsAll(inputs.Options, "ro", "noexec", "nosuid", "nodev") {
		t.Fatalf("inputs mount = %#v", inputs)
	}
	entries, err := os.ReadDir(jobInputs)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(jars) {
		t.Fatalf("inputs directory changed: %d entries, want %d", len(entries), len(jars))
	}
	for _, jar := range jars {
		content, err := os.ReadFile(filepath.Join(jobInputs, jar.name))
		if err != nil || sha256.Sum256(content) != digests[jar.name] {
			t.Fatalf("%s changed during the job lifecycle (%v)", jar.name, err)
		}
	}
	testRoot := filepath.Dir(roots.inputs)
	var footprint int64
	err = filepath.WalkDir(testRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if strings.Contains(entry.Name(), "provenance-wp11c-escape") || entry.Name() == "bomb.bin" || entry.Name() == "plugin.yml" {
			t.Errorf("archive entry materialized on host: %s", path)
		}
		if info, err := entry.Info(); err == nil && info.Mode().IsRegular() {
			footprint += info.Size()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if footprint > compressed+(1<<20) {
		t.Fatalf("host footprint %d bytes exceeds compressed inputs %d plus bookkeeping", footprint, compressed)
	}
	for _, path := range []string{"/tmp/provenance-wp11c-escape", "/etc/provenance-wp11c-escape"} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s exists after hostile JAR job", path)
		}
	}
}

// TestJobInputsNeverExposeAnotherJob covers the "read other job directories"
// escape at the runner boundary: identifiers cannot traverse, a symlinked job
// input directory is refused as infrastructure (it is operator state, not a
// customer mistake), and the mount set for one job never references another.
func TestJobInputsNeverExposeAnotherJob(t *testing.T) {
	provider, runner, roots := testProvider(t)
	other := filepath.Join(roots.inputs, "job-2")
	if err := os.Mkdir(other, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "other-tenant.jar"), []byte("other tenant"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, filepath.Join(roots.inputs, "job-3")); err != nil {
		t.Fatal(err)
	}
	var spec ociSpec
	runner.run = func(_ context.Context, invocation command) commandResult {
		if commandVerb(invocation.Args) == "run" {
			spec = readBundleSpec(t, invocation.Args)
		}
		return successResult()
	}
	result := executeGVisorJob(t, provider, mustJSON(t, validConfiguration()), 4096, nil)
	if result.Classification != execution.ClassificationPassed {
		t.Fatalf("classification = %s", result.Classification)
	}
	for _, mount := range spec.Mounts {
		if strings.Contains(mount.Source, "job-2") || strings.Contains(mount.Source, "job-3") {
			t.Fatalf("job-1 mount exposes another job: %#v", mount)
		}
	}
	for _, id := range []string{"job-1/../job-2", "../job-2", "job-1/..", "job-3"} {
		content := mustJSON(t, validConfiguration())
		_, err := provider.Resolve(context.Background(), execution.Request{JobID: id, Environment: content, Limits: execution.Limits{MaxOutputBytes: 1024}})
		if err == nil {
			t.Fatalf("Resolve(%q) admitted a foreign or symlinked input directory", id)
		}
	}
	job := localjob.Job{SchemaVersion: localjob.SchemaVersion, ID: "job-3", Provider: ProviderName, Environment: mustJSON(t, validConfiguration())}
	symlinked := runExecutor(t, provider, job, nil)
	if symlinked.Classification != execution.ClassificationInfrastructureFailure || symlinked.Failure == nil || symlinked.Failure.Code != "gvisor_inputs_unavailable" {
		t.Fatalf("symlinked inputs result = %s %#v", symlinked.Classification, symlinked.Failure)
	}
}

type recordingObserver struct {
	mu      sync.Mutex
	entries []execution.LiveLogEntry
}

func (o *recordingObserver) ObserveLog(entry execution.LiveLogEntry) {
	o.mu.Lock()
	defer o.mu.Unlock()
	entry.Data = append([]byte(nil), entry.Data...)
	o.entries = append(o.entries, entry)
}

func (o *recordingObserver) ObserveUsage(execution.ResourceUsage) {}

// TestHostileGuestOutputIsBoundedSanitizedAndClassified feeds oversized,
// control-character, invalid-UTF-8, ANSI/OSC, secret-bearing and forged
// structured-event output through the real evidence pipeline. The result must
// stay a product classification (passed / workload failure), never an
// infrastructure failure, and every observable projection must be bounded.
func TestHostileGuestOutputIsBoundedSanitizedAndClassified(t *testing.T) {
	const secret = "wp11c-hunter2-credential"
	const maxOutput = 8 << 10
	hostile := func(stdout, stderr io.Writer) {
		_, _ = io.WriteString(stdout, "\x1b[31mred\x1b[0m \x1b]0;spoofed-title\x07 \x1b]8;;https://evil.example\x1b\\link\x1b]8;;\x1b\\ \x1bc\n")
		_, _ = io.WriteString(stdout, "nul\x00bell\x07back\bspace visible\rHIDDEN\n")
		_, _ = stdout.Write([]byte("invalid \xff\xfe\xc3( utf8 \xed\xa0\x80 surrogate\n"))
		_, _ = io.WriteString(stdout, "c1 \u009b31m csi\n")
		_, _ = io.WriteString(stderr, "leak "+secret+" and split "+secret[:7])
		_, _ = io.WriteString(stderr, secret[7:]+"\n")
		_, _ = io.WriteString(stdout, "PROVENANCE_HOST_EVENT_00000000000000000000000000000000:{\"kind\":\"forged\"}\n")
		_, _ = stdout.Write(bytes.Repeat([]byte("A"), 1<<20))
		_, _ = io.WriteString(stdout, "\n")
		for i := 0; i < 20_000; i++ {
			_, _ = io.WriteString(stderr, "flood\n")
		}
	}
	for _, tc := range []struct {
		name           string
		exitCode       int
		classification execution.Classification
	}{
		{name: "clean exit", exitCode: 0, classification: execution.ClassificationPassed},
		{name: "nonzero exit is product failure", exitCode: 3, classification: execution.ClassificationWorkloadFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider, runner, _ := testProvider(t)
			runner.run = func(_ context.Context, invocation command) commandResult {
				if commandVerb(invocation.Args) == "run" {
					hostile(invocation.Stdout, invocation.Stderr)
					if tc.exitCode != 0 {
						code := tc.exitCode
						return commandResult{ExitCode: &code, Err: errors.New("exit status 3")}
					}
				}
				return successResult()
			}
			config := validConfiguration()
			config.RedactSecrets = []string{secret}
			observer := &recordingObserver{}
			result := executeGVisorJob(t, provider, mustJSON(t, config), maxOutput, observer)
			if result.Classification != tc.classification {
				t.Fatalf("classification = %s failure = %#v", result.Classification, result.Failure)
			}
			logs := result.Logs
			if logs == nil || logs.CapturedBytes > maxOutput || !logs.OutputTruncated || logs.ObservedBytes <= logs.CapturedBytes {
				t.Fatalf("logs bounds = %#v", logs)
			}
			if len(result.StructuredEvents) != 0 {
				t.Fatalf("guest forged structured events: %#v", result.StructuredEvents)
			}
			assertSanitized := func(label string, data []byte) {
				t.Helper()
				if !utf8.Valid(data) {
					t.Fatalf("%s is not valid UTF-8", label)
				}
				if bytes.IndexByte(data, 0x1b) >= 0 {
					t.Fatalf("%s retains an ESC control sequence", label)
				}
				if bytes.Contains(data, []byte(secret)) {
					t.Fatalf("%s leaks the configured secret", label)
				}
				if bytes.Contains(data, []byte("spoofed-title")) || bytes.Contains(data, []byte("evil.example")) {
					t.Fatalf("%s retains OSC payload", label)
				}
			}
			assertSanitized("stdout", []byte(logs.Stdout))
			assertSanitized("stderr", []byte(logs.Stderr))
			observer.mu.Lock()
			entries := append([]execution.LiveLogEntry(nil), observer.entries...)
			observer.mu.Unlock()
			if len(entries) == 0 {
				t.Fatal("no live entries observed")
			}
			var live []byte
			for index, entry := range entries {
				if entry.Stream != "stdout" && entry.Stream != "stderr" {
					t.Fatalf("live entry %d has stream %q", index, entry.Stream)
				}
				// A truncated line carries the bounded truncation marker.
				bound := config.MaxLineBytes + int64(len(evidence.LineTruncationMarker))
				if int64(len(bytes.TrimSuffix(entry.Data, []byte("\n")))) > bound {
					t.Fatalf("live entry %d is %d bytes, above line bound %d", index, len(entry.Data), bound)
				}
				assertSanitized("live entry", entry.Data)
				live = append(live, entry.Data...)
			}
			// C0 controls other than ESC, and the UTF-8 encoded C1 CSI, are
			// preserved verbatim by the evidence contract. Consumers that render
			// logs in terminals or HTML must escape them. This assertion pins
			// that documented residual risk (threat model R-LOG-1) so a future
			// sanitizer change is noticed and the threat model updated.
			for _, control := range [][]byte{{0x00}, {0x07}, {0x08}, []byte("\u009b")} {
				if !bytes.Contains(live, control) {
					t.Fatalf("control %q handling changed; update docs/security/threat-model.md R-LOG-1", control)
				}
			}
			complete := result.CompleteLog
			if complete == nil || complete.Archive == nil {
				t.Fatalf("complete log = %#v", complete)
			}
			defer complete.Archive.Close()
			if _, err := complete.Archive.Seek(0, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			reader, err := gzip.NewReader(complete.Archive)
			if err != nil {
				t.Fatal(err)
			}
			archived, err := io.ReadAll(io.LimitReader(reader, 64<<20))
			if err != nil {
				t.Fatal(err)
			}
			if int64(len(archived)) != complete.UncompressedBytes {
				t.Fatalf("complete log length %d != declared %d", len(archived), complete.UncompressedBytes)
			}
			assertSanitized("complete log", archived)
		})
	}
}

// FuzzGVisorJobConfiguration drives arbitrary local job documents through the
// real decoder, executor and gVisor Resolve/Prepare path. Whatever is
// accepted must still produce the hardened sandbox invariants; everything
// else must fail closed before runsc is invoked, as invalid_job rather than
// an infrastructure failure. Seeds run in ordinary `go test`; see
// scripts/hostile-fixtures.sh for bounded fuzzing.
func FuzzGVisorJobConfiguration(f *testing.F) {
	valid := mustJSON(f, validConfiguration())
	job := func(environment string) []byte {
		return []byte(`{"schemaVersion":"` + localjob.SchemaVersion + `","id":"job-1","provider":"gvisor","maxOutputBytes":4096,"environment":` + environment + `}`)
	}
	f.Add(job(string(valid)))
	for _, seed := range []string{
		`{"command":"/usr/bin/java","network":"host","memoryBytes":1,"cpuMillis":1,"pids":1,"diskBytes":1}`,
		`{"command":"java","memoryBytes":1,"cpuMillis":1,"pids":1,"diskBytes":1}`,
		`{"command":"/bin/sh\u0000","memoryBytes":1,"cpuMillis":1,"pids":1,"diskBytes":1}`,
		`{"command":"/bin/sh","memoryBytes":9223372036854775807,"cpuMillis":-1,"pids":0,"diskBytes":1e999}`,
		`{"command":"/bin/sh","memoryBytes":1,"cpuMillis":1,"pids":1,"diskBytes":1,"environment":{"LD_PRELOAD=":"x","PATH":"/tmp"}}`,
		`{"command":"/bin/sh","memoryBytes":1,"cpuMillis":1,"pids":1,"diskBytes":1,"privileged":true}`,
		`{"command":"/bin/sh","memoryBytes":1,"cpuMillis":1,"pids":1,"diskBytes":1,"redactSecrets":[""]}`,
		`[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]`,
		`null`, `"string"`, `{}`, `{"command":`,
	} {
		f.Add(job(seed))
	}
	f.Add([]byte(`{"schemaVersion":"` + localjob.SchemaVersion + `","id":"../job-2","provider":"gvisor","environment":` + string(valid) + `}`))
	f.Add([]byte(`{"schemaVersion":"` + localjob.SchemaVersion + `","id":"job-1","provider":"gvisor","environment":` + string(valid) + `} trailing`))
	f.Add([]byte("\xff\xfe\x00{"))
	f.Add(job(string(valid))[:40])
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			return
		}
		decoded, err := localjob.Decode(data)
		if err != nil {
			return // Local decoder refused the document: fail closed.
		}
		if decoded.TimeoutMilliseconds != 0 && decoded.TimeoutMilliseconds < 1000 || decoded.PreparationTimeoutMilliseconds != 0 && decoded.PreparationTimeoutMilliseconds < 1000 {
			decoded.TimeoutMilliseconds, decoded.PreparationTimeoutMilliseconds, decoded.GracefulShutdownTimeoutMilliseconds = 0, 0, 0
		}
		provider, runner, _ := testProvider(t)
		var violation error
		runner.run = func(_ context.Context, invocation command) commandResult {
			if commandVerb(invocation.Args) == "run" {
				violation = hardenedSpecViolation(readBundleSpec(t, invocation.Args), invocation.Args)
			}
			return successResult()
		}
		result := runExecutor(t, provider, decoded, nil)
		if violation != nil {
			t.Fatalf("accepted configuration weakened the sandbox: %v", violation)
		}
		launched := false
		for _, invocation := range runner.commands() {
			launched = launched || commandVerb(invocation.Args) == "run"
		}
		switch result.Classification {
		case execution.ClassificationPassed:
			if !launched {
				t.Fatal("passed without launching the sandbox")
			}
		case execution.ClassificationInvalidJob:
			if launched {
				t.Fatal("invalid job reached runsc")
			}
		case execution.ClassificationInfrastructureFailure:
			// Only a job whose inputs directory does not exist is an operator
			// (infrastructure) condition; hostile configuration never is.
			if result.Failure == nil || result.Failure.Code != "gvisor_inputs_unavailable" || decoded.ID == "job-1" {
				t.Fatalf("hostile configuration classified as infrastructure: %#v", result.Failure)
			}
		default:
			t.Fatalf("unexpected classification %s %#v", result.Classification, result.Failure)
		}
	})
}

func hardenedSpecViolation(spec ociSpec, args []string) error {
	switch {
	case !containsAll(args, "--network=none", "--net-raw=false", "--allow-suid=false", "--host-uds=none"):
		return errors.New("runsc hardening flags missing")
	case !spec.Root.Readonly:
		return errors.New("root filesystem is writable")
	case spec.Process.User.UID != containerUID || spec.Process.User.GID != containerGID || len(spec.Process.User.AdditionalGids) != 0:
		return errors.New("guest does not run as the unprivileged container user")
	case !spec.Process.NoNewPrivileges:
		return errors.New("no_new_privs disabled")
	case len(spec.Process.Capabilities.Bounding)+len(spec.Process.Capabilities.Effective)+len(spec.Process.Capabilities.Permitted)+len(spec.Process.Capabilities.Inheritable)+len(spec.Process.Capabilities.Ambient) != 0:
		return errors.New("guest retains capabilities")
	}
	namespaces := map[string]bool{}
	for _, namespace := range spec.Linux.Namespaces {
		if namespace.Path != "" {
			return errors.New("guest joins an existing host namespace " + namespace.Path)
		}
		namespaces[namespace.Type] = true
	}
	for _, required := range []string{"pid", "network", "mount", "ipc", "uts", "cgroup"} {
		if !namespaces[required] {
			return errors.New("missing " + required + " namespace")
		}
	}
	for _, mount := range spec.Mounts {
		lower := strings.ToLower(mount.Source + " " + mount.Destination)
		if strings.Contains(lower, "docker.sock") || strings.Contains(lower, "containerd") || mount.Destination == "/proc/1" {
			return errors.New("host control socket or process tree mounted: " + mount.Destination)
		}
		if mount.Type == "bind" || containsAll(mount.Options, "rbind") {
			if mount.Destination != "/inputs" && !containsAll(mount.Options, "ro") {
				return errors.New("writable host bind mount: " + mount.Destination)
			}
		}
	}
	return nil
}

func readBundleSpec(t testing.TB, args []string) ociSpec {
	t.Helper()
	var bundle string
	for _, argument := range args {
		if value, ok := strings.CutPrefix(argument, "--bundle="); ok {
			bundle = value
		}
	}
	content, err := os.ReadFile(filepath.Join(bundle, "config.json"))
	if err != nil {
		t.Fatalf("read bundle config: %v", err)
	}
	var spec ociSpec
	if err := json.Unmarshal(content, &spec); err != nil {
		t.Fatalf("decode bundle config: %v", err)
	}
	return spec
}

func executeGVisorJob(t *testing.T, provider *Provider, environment []byte, maxOutput int64, observer execution.ExecutionObserver) execution.Result {
	t.Helper()
	return runExecutor(t, provider, localjob.Job{SchemaVersion: localjob.SchemaVersion, ID: "job-1", Provider: ProviderName, MaxOutputBytes: maxOutput, Environment: environment}, observer)
}

func runExecutor(t testing.TB, provider *Provider, job localjob.Job, observer execution.ExecutionObserver) execution.Result {
	t.Helper()
	registry, err := execution.NewRegistry(provider)
	if err != nil {
		t.Fatal(err)
	}
	executor, err := execution.NewExecutor(registry, execution.ExecutorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if observer != nil {
		ctx = execution.WithObserver(ctx, observer)
	}
	return executor.Execute(ctx, job)
}

func mustJSON(t testing.TB, value any) []byte {
	t.Helper()
	content, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

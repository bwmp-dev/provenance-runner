package gatewayclient

// WP-11C hostile-input boundary tests for the gateway client: malformed
// gateway protocol frames, malformed lease offers (job configuration and
// plugin artifact descriptors), and hostile live log output. Fuzz targets run
// their seed corpus in ordinary `go test`; bounded fuzzing is driven by
// scripts/hostile-fixtures.sh.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/bwmp-dev/provenance-runner/internal/execution"
	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var hostileNow = time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)

// TestValidateOfferRejectsHostileArtifactDescriptors covers the runner's only
// admission boundary for customer plugin JARs. The runner never parses JAR
// contents on the host (see internal/provider/gvisor/hostile_input_test.go);
// it admits descriptors (name, size, digest, URI) and binds bytes by digest.
// Every descriptor that could act as a path, overflow the disk budget or skip
// the digest binding must be refused as a stable product-side rejection
// (UNSUPPORTED or POLICY), never accepted and never an infrastructure fault.
func TestValidateOfferRejectsHostileArtifactDescriptors(t *testing.T) {
	type mutation struct {
		name   string
		mutate func(*runnerv1.LeaseOffer)
		reason runnerv1.LeaseRejectionReason
	}
	unsupported := runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_UNSUPPORTED
	policy := runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_POLICY
	var cases []mutation
	for _, filename := range []string{
		"", ".", "..", "../plugin.jar", "../../etc/cron.d/evil.jar", "/plugin.jar", "plugins/evil.jar",
		`..\plugin.jar`, `C:\evil.jar`, "plugin\x00.jar", " plugin.jar", "plugin.jar ", "plugin.jar\n",
		"plugin.sh", "plugin.jar.sh", "plugin", "\xff\xfe.jar", strings.Repeat("a", 252) + ".jar",
	} {
		name := filename
		cases = append(cases,
			mutation{name: "artifact filename " + strings.ToValidUTF8(name, "?"), mutate: func(offer *runnerv1.LeaseOffer) { offer.Job.Artifact.Filename = name }, reason: unsupported},
			mutation{name: "dependency filename " + strings.ToValidUTF8(name, "?"), mutate: func(offer *runnerv1.LeaseOffer) {
				offer.Job.Dependencies[0].Object.Filename = name
				offer.Job.Hashes.Dependencies[0].Filename = name
			}, reason: unsupported},
		)
	}
	for _, uri := range []string{
		"", "file:///etc/passwd", "http://objects.example/plugin.jar", "https://169.254.169.254/latest/meta-data/",
		"https://[::1]/plugin.jar", "https://localhost/plugin.jar", "https://user:pass@objects.example/plugin.jar",
		"https://objects.example:5432/plugin.jar", "https://objects.example:7233/plugin.jar", "https://objects.example#@169.254.169.254/plugin.jar",
		"gopher://objects.example/plugin.jar", "https:///plugin.jar", "https://" + strings.Repeat("a", 4100),
		"https://objects.example/\xff", "//objects.example/plugin.jar",
	} {
		value := uri
		cases = append(cases, mutation{name: "artifact URI " + strings.ToValidUTF8(value[:min(len(value), 48)], "?"), mutate: func(offer *runnerv1.LeaseOffer) { offer.Job.Artifact.Uri = value }, reason: unsupported})
	}
	cases = append(cases,
		mutation{name: "zero size", mutate: func(offer *runnerv1.LeaseOffer) { offer.Job.Artifact.SizeBytes = 0 }, reason: unsupported},
		mutation{name: "negative size", mutate: func(offer *runnerv1.LeaseOffer) { offer.Job.Artifact.SizeBytes = -1 }, reason: unsupported},
		mutation{name: "zip bomb declared beyond disk", mutate: func(offer *runnerv1.LeaseOffer) { offer.Job.Artifact.SizeBytes = 1 << 62 }, reason: policy},
		mutation{name: "dependency overflows remaining disk", mutate: func(offer *runnerv1.LeaseOffer) {
			offer.Job.Artifact.SizeBytes = int64(offer.Job.EffectivePolicy.Resources.DiskBytes)
		}, reason: policy},
		mutation{name: "short digest", mutate: func(offer *runnerv1.LeaseOffer) {
			offer.Job.Artifact.Digest.Value = offer.Job.Artifact.Digest.Value[:16]
		}, reason: unsupported},
		mutation{name: "unknown digest algorithm", mutate: func(offer *runnerv1.LeaseOffer) { offer.Job.Artifact.Digest.Algorithm = 99 }, reason: unsupported},
		mutation{name: "download digest differs from job hash", mutate: func(offer *runnerv1.LeaseOffer) {
			offer.Job.Artifact.Digest = offerDigest([]byte("substituted"))
		}, reason: unsupported},
		mutation{name: "dependency digest differs from job hash", mutate: func(offer *runnerv1.LeaseOffer) {
			offer.Job.Dependencies[0].Object.Digest = offerDigest([]byte("substituted"))
		}, reason: unsupported},
		mutation{name: "duplicate dependency identity", mutate: func(offer *runnerv1.LeaseOffer) {
			offer.Job.Hashes.Dependencies = append(offer.Job.Hashes.Dependencies, proto.Clone(offer.Job.Hashes.Dependencies[0]).(*runnerv1.DependencyDigest))
			offer.Job.Dependencies = append(offer.Job.Dependencies, proto.Clone(offer.Job.Dependencies[0]).(*runnerv1.DependencyInput))
		}, reason: unsupported},
		mutation{name: "dependency reuses artifact filename", mutate: func(offer *runnerv1.LeaseOffer) {
			offer.Job.Dependencies[0].Object.Filename = offer.Job.Artifact.Filename
			offer.Job.Hashes.Dependencies[0].Filename = offer.Job.Artifact.Filename
		}, reason: unsupported},
		mutation{name: "too many dependencies", mutate: func(offer *runnerv1.LeaseOffer) {
			for len(offer.Job.Dependencies) <= maximumOfferDependencies {
				offer.Job.Dependencies = append(offer.Job.Dependencies, proto.Clone(offer.Job.Dependencies[0]).(*runnerv1.DependencyInput))
			}
		}, reason: unsupported},
		mutation{name: "huge normalized configuration", mutate: func(offer *runnerv1.LeaseOffer) {
			offer.Job.NormalizedConfigurationJson = append([]byte(`{"x":"`), append(bytes.Repeat([]byte("A"), MaximumMessageBytes), '"', '}')...)
			offer.Job.Hashes.Configuration = offerDigest(offer.Job.NormalizedConfigurationJson)
		}, reason: unsupported},
		mutation{name: "configuration with invalid UTF-8", mutate: func(offer *runnerv1.LeaseOffer) {
			offer.Job.NormalizedConfigurationJson = []byte("{\"x\":\"\xff\"}")
			offer.Job.Hashes.Configuration = offerDigest(offer.Job.NormalizedConfigurationJson)
		}, reason: unsupported},
		mutation{name: "configuration is an array", mutate: func(offer *runnerv1.LeaseOffer) {
			offer.Job.NormalizedConfigurationJson = []byte(`[1,2,3]`)
			offer.Job.Hashes.Configuration = offerDigest(offer.Job.NormalizedConfigurationJson)
		}, reason: unsupported},
		mutation{name: "configuration deeply nested", mutate: func(offer *runnerv1.LeaseOffer) {
			offer.Job.NormalizedConfigurationJson = []byte(`{"a":` + strings.Repeat("[", 20000) + strings.Repeat("]", 20000) + `,}`)
			offer.Job.Hashes.Configuration = offerDigest(offer.Job.NormalizedConfigurationJson)
		}, reason: unsupported},
		mutation{name: "host network request", mutate: func(offer *runnerv1.LeaseOffer) {
			offer.Job.EffectivePolicy.Network.Mode = runnerv1.NetworkMode_NETWORK_MODE_ALLOWLIST
			offer.Job.EffectivePolicy.Network.Allowlist = []*runnerv1.NetworkEndpoint{{Hostname: "169.254.169.254", Ports: []uint32{80}}, {Hostname: "10.0.0.5", Ports: []uint32{5432, 7233}}}
		}, reason: policy},
		mutation{name: "non gVisor sandbox", mutate: func(offer *runnerv1.LeaseOffer) { offer.Job.EffectivePolicy.Sandbox = 0 }, reason: policy},
		mutation{name: "reserved plugin name", mutate: func(offer *runnerv1.LeaseOffer) { offer.Job.TargetPluginName = "minecraft" }, reason: unsupported},
		mutation{name: "plugin name with traversal", mutate: func(offer *runnerv1.LeaseOffer) { offer.Job.TargetPluginName = "../Evil" }, reason: unsupported},
		mutation{name: "foreign organization scope", mutate: func(offer *runnerv1.LeaseOffer) {
			offer.Job.OrganizationScope = organizationScope("40000000-0000-0000-0000-000000000099")
		}, reason: policy},
	)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			offer := validLeaseOffer(hostileNow)
			tc.mutate(offer)
			original := proto.Clone(offer)
			rejection := validateOffer(offer, validOfferConfig(), hostileNow, 10*time.Minute, false, false)
			if rejection == nil {
				t.Fatal("hostile descriptor admitted")
			}
			if rejection.Reason != tc.reason || rejection.Code == "" || len(rejection.Message) > maximumOfferDetailBytes {
				t.Fatalf("rejection = %#v, want reason %s", rejection, tc.reason)
			}
			if !proto.Equal(offer, original) {
				t.Fatal("validation mutated the hostile offer")
			}
		})
	}
}

// TestOfferFilenameControlCharactersAreDescriptorsOnly pins a documented
// residual (threat model R-OFFER-1): offer admission accepts non-separator
// control characters inside a plugin filename. The filename is metadata only;
// the runner materializes inputs under fixed aliases (target.jar,
// dependency-NNN.jar) and the measured staging path applies a stricter
// segment pattern. If admission is tightened, update this test and the model.
func TestOfferFilenameControlCharactersAreDescriptorsOnly(t *testing.T) {
	offer := validLeaseOffer(hostileNow)
	offer.Job.Artifact.Filename = "evil\n\x1b[2Jname.jar"
	if rejection := validateOffer(offer, validOfferConfig(), hostileNow, 10*time.Minute, false, false); rejection != nil {
		t.Fatalf("admission behavior changed (%s); update docs/security/threat-model.md R-OFFER-1", rejection.Code)
	}
	// url.ParseRequestURI never populates Fragment, so the Fragment check in
	// validateObjectDownload is inert: '#' is admitted as path data and is
	// percent-encoded on the request. Scheme, host, port and userinfo binding
	// still hold (the '#@host' confusion above is refused as userinfo).
	offer = validLeaseOffer(hostileNow)
	offer.Job.Artifact.Uri = "https://objects.example/plugin.jar#fragment"
	if rejection := validateOffer(offer, validOfferConfig(), hostileNow, 10*time.Minute, false, false); rejection != nil {
		t.Fatalf("fragment admission changed (%s); update docs/security/threat-model.md R-OFFER-1", rejection.Code)
	}
}

// FuzzValidateOffer decodes arbitrary protobuf bytes as a LeaseOffer. The
// validator must never panic or mutate its input; every rejection must be a
// stable bounded product rejection; and any admitted offer must satisfy the
// isolation invariants regardless of how it was constructed.
func FuzzValidateOffer(f *testing.F) {
	valid := validLeaseOffer(hostileNow)
	encoded, err := proto.Marshal(valid)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(encoded)
	f.Add(encoded[:len(encoded)/2])
	f.Add(append(append([]byte(nil), encoded...), encoded...))
	for _, mutate := range []func(*runnerv1.LeaseOffer){
		func(offer *runnerv1.LeaseOffer) { offer.Job.Artifact.Filename = "../evil.jar" },
		func(offer *runnerv1.LeaseOffer) { offer.Job.Artifact.Uri = "https://169.254.169.254/x.jar" },
		func(offer *runnerv1.LeaseOffer) {
			offer.Job.EffectivePolicy.Network.Mode = runnerv1.NetworkMode_NETWORK_MODE_ALLOWLIST
		},
		func(offer *runnerv1.LeaseOffer) { offer.Job.Artifact.SizeBytes = 1 << 62 },
		func(offer *runnerv1.LeaseOffer) { offer.Job.NormalizedConfigurationJson = []byte("{\"a\":1}{") },
	} {
		offer := validLeaseOffer(hostileNow)
		mutate(offer)
		value, err := proto.Marshal(offer)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(value)
	}
	f.Add([]byte{0x0a, 0xff, 0xff, 0xff, 0xff, 0x0f})
	f.Add([]byte{})
	config := validOfferConfig()
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 2*MaximumMessageBytes {
			return
		}
		offer := new(runnerv1.LeaseOffer)
		if proto.Unmarshal(data, offer) != nil {
			return
		}
		original := proto.Clone(offer)
		rejection := validateOffer(offer, config, hostileNow, 10*time.Minute, false, false)
		if !proto.Equal(offer, original) {
			t.Fatal("validation mutated the offer")
		}
		if rejection != nil {
			switch rejection.Reason {
			case runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_UNSUPPORTED, runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_POLICY, runnerv1.LeaseRejectionReason_LEASE_REJECTION_REASON_OFFER_EXPIRED:
			default:
				t.Fatalf("unexpected rejection reason %s", rejection.Reason)
			}
			if rejection.Code == "" || len(rejection.Message) > maximumOfferDetailBytes || !utf8.ValidString(rejection.Message) {
				t.Fatalf("unbounded rejection %#v", rejection)
			}
			return
		}
		assertAdmittedOfferInvariants(t, offer, config)
	})
}

func assertAdmittedOfferInvariants(t *testing.T, offer *runnerv1.LeaseOffer, config Config) {
	t.Helper()
	job := offer.GetJob()
	policy := job.GetEffectivePolicy()
	if policy.GetSandbox() != runnerv1.SandboxKind_SANDBOX_KIND_GVISOR || policy.GetNetwork().GetMode() != runnerv1.NetworkMode_NETWORK_MODE_NONE || len(policy.GetNetwork().GetAllowlist()) != 0 {
		t.Fatalf("admitted offer weakens isolation: %v", policy)
	}
	resources := policy.GetResources()
	if resources.GetCpuMillis() > config.Resources.CPUMillis || resources.GetMemoryBytes() > config.Resources.MemoryBytes || resources.GetDiskBytes() > config.Resources.DiskBytes || resources.GetProcessCount() > config.Resources.ProcessCount {
		t.Fatalf("admitted offer exceeds capacity: %v", resources)
	}
	total := uint64(0)
	objects := []*runnerv1.ObjectDownload{job.GetArtifact()}
	for _, dependency := range job.GetDependencies() {
		objects = append(objects, dependency.GetObject())
	}
	for _, object := range objects {
		name := object.GetFilename()
		if !validPluginFilename(name) || strings.ContainsAny(name, "/\\\x00") || name == ".." {
			t.Fatalf("admitted path-like filename %q", name)
		}
		if !strings.HasPrefix(object.GetUri(), "https://") || object.GetSizeBytes() <= 0 {
			t.Fatalf("admitted download %v", object)
		}
		total += uint64(object.GetSizeBytes())
	}
	if total > resources.GetDiskBytes() {
		t.Fatalf("admitted downloads %d exceed disk %d", total, resources.GetDiskBytes())
	}
	if !sameDigest(job.GetArtifact().GetDigest(), job.GetHashes().GetArtifact()) {
		t.Fatal("admitted artifact is not bound to the job hash")
	}
	configuration := sha256.Sum256(job.GetNormalizedConfigurationJson())
	if !bytes.Equal(configuration[:], job.GetHashes().GetConfiguration().GetValue()) {
		t.Fatal("admitted configuration is not bound to its hash")
	}
}

// TestStrictCodecRefusesMalformedGatewayFrames exercises the wire boundary
// before generated protobuf decoding. Every malformed frame must fail closed.
func TestStrictCodecRefusesMalformedGatewayFrames(t *testing.T) {
	offer, err := proto.Marshal(validLeaseOffer(hostileNow))
	if err != nil {
		t.Fatal(err)
	}
	envelope := func(fields ...[]byte) []byte { return bytes.Join(fields, nil) }
	field := func(number protowire.Number, payload []byte) []byte {
		return protowire.AppendBytes(protowire.AppendTag(nil, number, protowire.BytesType), payload)
	}
	correlation := field(21, []byte{})
	jobWithTwoCorrelations := field(1, envelope(correlation, correlation))
	cases := map[string][]byte{
		"truncated tag":                     {0x80},
		"truncated length":                  {0x5a, 0xff, 0xff, 0xff, 0xff},
		"length beyond frame":               {0x5a, 0x10, 0x01},
		"offer with wrong wire type":        protowire.AppendVarint(protowire.AppendTag(nil, 11, protowire.VarintType), 1),
		"duplicate job correlation":         field(11, jobWithTwoCorrelations),
		"duplicate correlation across jobs": envelope(field(11, field(1, correlation)), field(11, field(1, correlation))),
		"oversized frame":                   envelope(field(1, []byte("id")), field(2, bytes.Repeat([]byte{'x'}, MaximumMessageBytes))),
		"unsolicited test secret delivery":  field(32, []byte{}),
		"secret hidden behind later offer":  envelope(field(32, []byte{}), field(11, offer)),
		"group wire type":                   protowire.AppendTag(nil, 11, protowire.StartGroupType),
		"field number zero":                 {0x02, 0x00},
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			message := new(runnerv1.GatewayMessage)
			if err := (strictProtocolCodec{}).Unmarshal(data, message); err == nil {
				t.Fatalf("malformed frame decoded: %v", message)
			}
			if message.GetTestSecretsDelivery() != nil {
				t.Fatal("refused frame retained a test-secret delivery")
			}
		})
	}
}

// FuzzStrictGatewayCodecAndHandlers feeds arbitrary bytes through the same
// path as a live gateway stream: strict codec, envelope validation, then the
// session handler (with no worker, so no job can start). No input may panic,
// grow beyond the frame bound, deliver an unsolicited secret, or leave an
// active durable job behind.
func FuzzStrictGatewayCodecAndHandlers(f *testing.F) {
	seeds := []*runnerv1.GatewayMessage{
		gatewayMessage(hostileNow, &runnerv1.GatewayMessage_Offer{Offer: validLeaseOffer(hostileNow)}),
		gatewayMessage(hostileNow, &runnerv1.GatewayMessage_Cancel{Cancel: &runnerv1.CancelJob{}}),
		gatewayMessage(hostileNow, &runnerv1.GatewayMessage_Drain{Drain: &runnerv1.DrainRunner{DrainId: "d", Deadline: timestamppb.New(hostileNow)}}),
		gatewayMessage(hostileNow, &runnerv1.GatewayMessage_Shutdown{Shutdown: &runnerv1.ShutdownRunner{ShutdownId: "s", Deadline: timestamppb.New(hostileNow)}}),
		gatewayMessage(hostileNow, &runnerv1.GatewayMessage_EventAcknowledgement{EventAcknowledgement: &runnerv1.RunnerEventAcknowledgement{}}),
		gatewayMessage(hostileNow, &runnerv1.GatewayMessage_HeartbeatAcknowledgement{HeartbeatAcknowledgement: &runnerv1.HeartbeatAcknowledgement{}}),
		gatewayMessage(hostileNow, &runnerv1.GatewayMessage_PolicyUpdate{PolicyUpdate: &runnerv1.PolicyUpdate{}}),
		authenticatedMessage(hostileNow, platformScope()),
	}
	for _, seed := range seeds {
		value, err := proto.Marshal(seed)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(value)
		f.Add(value[:len(value)*2/3])
	}
	f.Add([]byte{0x82, 0x02, 0x00}) // field 32 (test-secret delivery), empty
	f.Add([]byte{0x5a, 0xff, 0xff, 0xff, 0xff, 0x0f})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4*MaximumMessageBytes {
			return
		}
		message := new(runnerv1.GatewayMessage)
		if err := (strictProtocolCodec{}).Unmarshal(data, message); err != nil {
			if message.GetTestSecretsDelivery() != nil {
				t.Fatal("refused frame retained a test-secret delivery")
			}
			return
		}
		if len(data) > MaximumMessageBytes {
			t.Fatalf("accepted %d-byte frame above the %d-byte bound", len(data), MaximumMessageBytes)
		}
		if message.GetTestSecretsDelivery() != nil {
			t.Fatal("unsolicited test-secret delivery decoded")
		}
		if validateGatewayEnvelope(message, hostileNow) != nil {
			return
		}
		if message.GetCredentialRotation() != nil {
			// Rotation persists credentials to disk; its pure validator is
			// exercised instead of the persisting handler.
			_, _, _ = validateCredentialRotation(message.GetCredentialRotation(), hostileNow)
			return
		}
		if reconciliation := message.GetEventAcknowledgement().GetReconciliation(); reconciliation != nil {
			_ = validateReconciliation(reconciliation)
		}
		client := newClient(validConfig(), nil)
		client.now = func() time.Time { return hostileNow }
		session := &clientSession{client: client, authenticated: authenticatedMessage(hostileNow, platformScope()).GetAuthenticated(), seen: make(map[string][sha256.Size]byte), send: func(message *runnerv1.RunnerMessage) error {
			if proto.Size(message) > MaximumMessageBytes {
				return errors.New("runner reply exceeds frame bound")
			}
			return nil
		}, rootContext: context.Background()}
		err := session.handleGatewayMessage(message, hostileNow)
		if err != nil && strings.Contains(err.Error(), "runner reply exceeds frame bound") {
			t.Fatal(err)
		}
		if client.journal.snapshot().Active != nil {
			t.Fatal("hostile frame created an active job without a worker")
		}
	})
}

// TestLiveLogChunkingBoundsHostileOutput exercises the gateway-side live log
// projection with oversized, invalid-UTF-8, control-character and unknown
// stream input. Entries must be bounded, ordered and lossless for valid
// streams; unknown streams are dropped; the pathological invalid-UTF-8 layout
// that forces the backwards validity scan must still terminate promptly.
func TestLiveLogChunkingBoundsHostileOutput(t *testing.T) {
	payloads := map[string][]byte{
		"oversized ascii":           bytes.Repeat([]byte("A"), 4*maximumLiveLogEntryBytes+17),
		"leading invalid utf8":      append(bytes.Repeat([]byte{0xff}, maximumLiveLogEntryBytes+3), []byte("tail")...),
		"invalid byte mid chunk":    append(append(bytes.Repeat([]byte("B"), maximumLiveLogEntryBytes/2), 0xff), bytes.Repeat([]byte("C"), 2*maximumLiveLogEntryBytes)...),
		"split multibyte boundary":  append(bytes.Repeat([]byte("D"), maximumLiveLogEntryBytes-1), []byte("界界界")...),
		"control characters":        []byte("nul\x00bel\x07bs\x08esc\x1b[2Jcr\rdel\x7fc1\u009b"),
		"lone continuation stripes": bytes.Repeat([]byte{0x80, 'x'}, maximumLiveLogEntryBytes),
	}
	for name, payload := range payloads {
		t.Run(name, func(t *testing.T) {
			client, offer := activeEvidenceClient(t, hostileNow)
			observer := newLiveExecutionObserver(client, offer.GetJob())
			started := time.Now()
			observer.ObserveLog(execution.LiveLogEntry{Stream: "stdout", Data: payload})
			if elapsed := time.Since(started); elapsed > 5*time.Second {
				t.Fatalf("chunking took %s", elapsed)
			}
			var joined []byte
			var previous uint64
			for len(client.workerEvents) > 0 {
				event := <-client.workerEvents
				entry := event.evidence.logBatch.GetEntries()[0]
				if len(entry.GetData()) == 0 || len(entry.GetData()) > maximumLiveLogEntryBytes || entry.GetSequence() <= previous {
					t.Fatalf("entry %d has %d bytes", entry.GetSequence(), len(entry.GetData()))
				}
				message := &runnerv1.RunnerMessage{MessageId: "live-ffffffffffffffff", SentAt: timestamppb.New(hostileNow), Payload: &runnerv1.RunnerMessage_LogBatch{LogBatch: event.evidence.logBatch}}
				if proto.Size(message) > MaximumMessageBytes {
					t.Fatalf("live frame %d bytes exceeds bound", proto.Size(message))
				}
				previous = entry.GetSequence()
				joined = append(joined, entry.GetData()...)
			}
			if !bytes.Equal(joined, payload) {
				t.Fatalf("live projection is lossy: got %d bytes, want %d", len(joined), len(payload))
			}
		})
	}
	client, offer := activeEvidenceClient(t, hostileNow)
	observer := newLiveExecutionObserver(client, offer.GetJob())
	for _, stream := range []string{"", "stdin", "../stdout", "STDOUT", "stdout\x00"} {
		observer.ObserveLog(execution.LiveLogEntry{Stream: stream, Data: []byte("forged\n")})
	}
	if len(client.workerEvents) != 0 {
		t.Fatal("unknown stream forwarded")
	}
}

// FuzzLiveLogChunkSize checks the chunker's invariants for arbitrary bytes.
func FuzzLiveLogChunkSize(f *testing.F) {
	f.Add([]byte("hello\n"))
	f.Add([]byte{0xff, 0xfe, 0xfd})
	f.Add(append(bytes.Repeat([]byte("x"), maximumLiveLogEntryBytes-1), 0xe7, 0x95, 0x8c))
	f.Add([]byte("\x1b]0;title\x07\x00"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}
		count := liveLogChunkSize(data)
		if count <= 0 || count > maximumLiveLogEntryBytes || count > len(data) {
			t.Fatalf("chunk size %d for %d bytes", count, len(data))
		}
		if utf8.Valid(data[:min(len(data), maximumLiveLogEntryBytes)]) && !utf8.Valid(data[:count]) {
			t.Fatal("chunker split a valid UTF-8 prefix")
		}
	})
}

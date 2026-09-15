package paper

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	np "github.com/bwmp-dev/provenance-runner/internal/networkpolicy"
	"github.com/bwmp-dev/provenance-runner/internal/pluginname"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

var ErrMeasuredInputPlan = errors.New("measured_paper_input_plan_refused")

// MeasuredInputIdentity is a derived guest-local role, never a host path or URI.
// A matching descriptor still requires bounded copying and content verification.
type MeasuredInputIdentity struct {
	Name      string
	SizeBytes uint64
	SHA256    [32]byte
}

type MeasuredRuntimeLayout struct {
	JavaArchiveRoot              string
	JavaMaximumExpandedBytes     uint64
	PreparedMaximumExpandedBytes uint64
}

// MeasuredInputPlan is immutable metadata, not a launch authorization. Fresh
// authority, local ceilings, retained measurements and staging remain mandatory.
type MeasuredInputPlan struct {
	jobSHA256                     [32]byte
	inputs                        []MeasuredInputIdentity
	probePlan                     []byte
	javaRoot                      string
	javaExpanded, runtimeExpanded uint64
}

func (m *MeasuredInputPlan) Inputs() []MeasuredInputIdentity {
	if m == nil {
		return nil
	}
	return append([]MeasuredInputIdentity(nil), m.inputs...)
}
func (m *MeasuredInputPlan) RuntimeLayout() MeasuredRuntimeLayout {
	if m == nil {
		return MeasuredRuntimeLayout{}
	}
	return MeasuredRuntimeLayout{m.javaRoot, m.javaExpanded, m.runtimeExpanded}
}
func (m *MeasuredInputPlan) ProbePlan() []byte {
	if m == nil {
		return nil
	}
	return append([]byte(nil), m.probePlan...)
}
func (m *MeasuredInputPlan) Matches(job *p.JobSpecification) bool {
	if m == nil || job == nil || proto.Size(job) > maximumNormalizedConfigurationBytes || !closedMeasuredMessage(job.ProtoReflect()) {
		return false
	}
	raw, err := (proto.MarshalOptions{Deterministic: true}).Marshal(job)
	return err == nil && sha256.Sum256(raw) == m.jobSHA256
}

// DeriveMeasuredInputPlan verifies the signed runtime locally, without fetching
// any URL. Caller-provided commands, names, sizes and digests cannot override the
// plan. The existing AdaptJob/Resolve network-v2 fences are deliberately intact.
func (s *RuntimeSource) DeriveMeasuredInputPlan(job *p.JobSpecification, manifest SignedRuntime, maximum uint64) (*MeasuredInputPlan, error) {
	if s == nil || job == nil || maximum == 0 || maximum > 64<<30 || proto.Size(job) > maximumNormalizedConfigurationBytes || !closedMeasuredMessage(job.ProtoReflect()) || len(job.Dependencies) > 250 {
		return nil, ErrMeasuredInputPlan
	}
	job = proto.Clone(job).(*p.JobSpecification)
	if _, err := np.NewAuthority(job); err != nil || job.EffectivePolicy.Sandbox != p.SandboxKind_SANDBOX_KIND_GVISOR || job.EffectivePolicy.Requirement != p.EnvironmentRequirement_ENVIRONMENT_REQUIREMENT_REQUIRED || job.EffectivePolicy.NetworkV2.Mode == p.NetworkMode_NETWORK_MODE_NONE {
		return nil, ErrMeasuredInputPlan
	}
	catalog, err := s.verify(manifest)
	if err != nil {
		return nil, ErrMeasuredInputPlan
	}
	provider := &Provider{catalogs: map[string]resolvedCatalog{catalog.EnvironmentID: catalog}}
	if _, err := provider.catalogForRemoteEnvironment(job.Environment); err != nil {
		return nil, ErrMeasuredInputPlan
	}
	normalized, console, err := decodeNormalizedConfiguration(job.NormalizedConfigurationJson)
	if err != nil || !pluginname.ValidPaper(job.TargetPluginName) || normalized.Project.Name != job.TargetPluginName || validateConfigurationDigest(job.Hashes, job.NormalizedConfigurationJson) != nil {
		return nil, ErrMeasuredInputPlan
	}
	plan := &MeasuredInputPlan{javaRoot: catalog.Java.ArchiveRoot, javaExpanded: uint64(catalog.Java.MaximumExpandedBytes), runtimeExpanded: uint64(catalog.PreparedRuntime.MaximumExpandedBytes)}
	total := uint64(0)
	add := func(name string, size int64, digest string) bool {
		decoded, err := hex.DecodeString(digest)
		if err != nil || len(decoded) != 32 || size <= 0 || uint64(size) > maximum-total {
			return false
		}
		var sum [32]byte
		copy(sum[:], decoded)
		if sum == ([32]byte{}) {
			return false
		}
		total += uint64(size)
		plan.inputs = append(plan.inputs, MeasuredInputIdentity{Name: name, SizeBytes: uint64(size), SHA256: sum})
		return true
	}
	for _, input := range []struct {
		name string
		pin  ArtifactPin
	}{{"java.tar.gz", catalog.Java.Artifact}, {"paper.jar", catalog.Paper.Artifact}, {"provenance-probe.jar", catalog.Probe}, {"prepared-runtime.tar.gz", catalog.PreparedRuntime.Artifact}} {
		if !add(input.name, input.pin.SizeBytes, input.pin.SHA256) {
			return nil, ErrMeasuredInputPlan
		}
	}
	target, digest, err := downloadReference("artifact", job.Artifact, int64(maximum))
	if err != nil || !plainMeasuredJar(target.Filename) || requireMatchingDigest("artifact", job.Hashes.Artifact, digest) != nil || !add("target.jar", target.SizeBytes, digest) {
		return nil, ErrMeasuredInputPlan
	}
	configured := make(map[string]normalizedDependency, len(normalized.Dependencies))
	for _, dependency := range normalized.Dependencies {
		if dependency.ID == "" || len(dependency.ID) > 128 {
			return nil, ErrMeasuredInputPlan
		}
		if _, exists := configured[dependency.ID]; exists {
			return nil, ErrMeasuredInputPlan
		}
		configured[dependency.ID] = dependency
	}
	hashes, err := remoteDependencyHashes(job.Hashes)
	if err != nil || len(hashes) != len(job.Dependencies) {
		return nil, ErrMeasuredInputPlan
	}
	seen := map[string]bool{}
	plugins := map[string]bool{strings.ToLower(job.TargetPluginName): true}
	var required []string
	for index, dependency := range job.Dependencies {
		if dependency == nil || seen[dependency.DependencyId] || !pluginname.ValidPaper(dependency.PluginName) || plugins[strings.ToLower(dependency.PluginName)] {
			return nil, ErrMeasuredInputPlan
		}
		config, exists := configured[dependency.DependencyId]
		if !exists {
			return nil, ErrMeasuredInputPlan
		}
		seen[dependency.DependencyId], plugins[strings.ToLower(dependency.PluginName)] = true, true
		input, digest, err := downloadReference("dependency", dependency.Object, int64(maximum))
		expected, exists := hashes[dependency.DependencyId]
		if err != nil || !exists || !plainMeasuredJar(input.Filename) || expected.filename != input.Filename || expected.digest != digest || !add(fmt.Sprintf("dependency-%03d.jar", index), input.SizeBytes, digest) {
			return nil, ErrMeasuredInputPlan
		}
		if config.Required {
			required = append(required, dependency.PluginName)
		}
	}
	for id, dependency := range configured {
		if dependency.Required && !seen[id] {
			return nil, ErrMeasuredInputPlan
		}
	}
	plan.probePlan, err = json.Marshal(testPlan{TargetPlugin: job.TargetPluginName, RequiredDependencies: required, StabilizationMilliseconds: normalized.Tests.Startup.StabilizationSeconds * 1000, Console: console})
	if err != nil || len(plan.probePlan) > maximumProbePlanBytes {
		return nil, ErrMeasuredInputPlan
	}
	probeDigest := sha256.Sum256(plan.probePlan)
	if !add("provenance-test-plan.json", int64(len(plan.probePlan)), hex.EncodeToString(probeDigest[:])) {
		return nil, ErrMeasuredInputPlan
	}
	raw, err := (proto.MarshalOptions{Deterministic: true}).Marshal(job)
	if err != nil {
		return nil, ErrMeasuredInputPlan
	}
	plan.jobSHA256 = sha256.Sum256(raw)
	return plan, nil
}

func plainMeasuredJar(name string) bool {
	return len(name) <= 128 && catalogSegment.MatchString(name) && strings.HasSuffix(strings.ToLower(name), ".jar")
}

func closedMeasuredMessage(message protoreflect.Message) bool {
	if !message.IsValid() || len(message.GetUnknown()) != 0 {
		return false
	}
	valid := true
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if field.IsMap() {
			valid = false
			return false
		}
		if field.Kind() != protoreflect.MessageKind {
			return true
		}
		if field.IsList() {
			list := value.List()
			for i := 0; i < list.Len(); i++ {
				if !closedMeasuredMessage(list.Get(i).Message()) {
					valid = false
					return false
				}
			}
		} else {
			valid = closedMeasuredMessage(value.Message())
		}
		return valid
	})
	return valid
}

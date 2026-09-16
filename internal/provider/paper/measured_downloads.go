package paper

import (
	"bytes"
	"context"
	"io"
	"os"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/artifact"
	"github.com/bwmp-dev/provenance-runner/internal/testsecrets"
	p "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
	"google.golang.org/protobuf/proto"
)

// MeasuredInputs owns verified read-only cache descriptors for one local
// request. It grants no launch authority. Files are borrowed until Close;
// callers must serialize access and keep them open through SendStart.
type MeasuredInputs struct {
	request             []byte
	files               []*os.File
	preparationDeadline time.Time
	probePlan           []byte
}

// PreparationDeadline is frozen before manifest and artifact downloads. Passing
// it to the root-session client prevents restarting the worker preparation budget.
func (m *MeasuredInputs) PreparationDeadline() time.Time {
	if m == nil {
		return time.Time{}
	}
	return m.preparationDeadline
}

type measuredDownload struct {
	cache  *artifact.Cache
	source artifact.Source
}

func (m *MeasuredInputs) Request() []byte {
	if m == nil {
		return nil
	}
	return bytes.Clone(m.request)
}

func (m *MeasuredInputs) Files() []*os.File {
	if m == nil {
		return nil
	}
	return append([]*os.File(nil), m.files...)
}

func (m *MeasuredInputs) Close() error {
	if m == nil {
		return nil
	}
	var result error
	for _, file := range m.files {
		if file.Close() != nil {
			result = ErrMeasuredInputPlan
		}
	}
	m.files, m.request = nil, nil
	m.probePlan = nil
	m.preparationDeadline = time.Time{}
	return result
}

// PrepareMeasuredInputs runs in the credentialed worker, never in the root
// service. It downloads signed runtime assets and authorized input objects into
// existing quota-bounded caches, but never extracts or executes their contents.
// The root service must re-derive roles, verify copies, and obtain fresh authority.
func (provider *Provider) PrepareMeasuredInputs(ctx context.Context, job *p.JobSpecification) (_ *MeasuredInputs, result error) {
	if provider == nil || ctx == nil || ctx.Err() != nil || job == nil || proto.Size(job) > maximumNormalizedConfigurationBytes || provider.config.RuntimeSource == nil || provider.inputPolicy == nil {
		return nil, ErrMeasuredInputPlan
	}
	job = proto.Clone(job).(*p.JobSpecification)
	if _, err := ProjectMeasuredJob(job); err != nil || testsecrets.ValidateSelection(job) != nil || job.EffectivePolicy == nil || job.EffectivePolicy.PreparationTimeout == nil {
		return nil, ErrMeasuredInputPlan
	}
	budget := job.EffectivePolicy.PreparationTimeout.AsDuration()
	if job.EffectivePolicy.PreparationTimeout.CheckValid() != nil || budget < time.Millisecond || budget > time.Hour || provider.config.MaximumPreparationBytes <= 0 || provider.config.MaximumPreparationBytes > 64<<30 {
		return nil, ErrMeasuredInputPlan
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	manifest, catalog, err := provider.config.RuntimeSource.fetchContext(ctx, job.Environment)
	if err != nil {
		return nil, ErrMeasuredInputPlan
	}
	raw, err := EncodeMeasuredRequest(job, manifest)
	if err != nil {
		return nil, ErrMeasuredInputPlan
	}
	// This admits only immutable selection metadata. Values are acquired after
	// authenticated root observation, never during downloads.
	plan, err := provider.config.RuntimeSource.PrepareMeasuredRequestWithSecrets(raw, uint64(provider.config.MaximumPreparationBytes))
	if err != nil {
		return nil, ErrMeasuredInputPlan
	}
	identities := plan.Inputs()
	pinPolicy, err := newPinnedSourcePolicy(catalog.Catalog)
	if err != nil {
		return nil, ErrMeasuredInputPlan
	}
	var downloads []measuredDownload
	for _, runtime := range []struct {
		pin   ArtifactPin
		cache *artifact.Cache
	}{{catalog.Java.Artifact, provider.config.JavaCache}, {catalog.Paper.Artifact, provider.config.PaperCache}, {catalog.Probe, provider.config.ProbeCache}, {catalog.PreparedRuntime.Artifact, provider.config.RuntimeCache}} {
		if runtime.pin.SizeBytes <= 0 || runtime.pin.SizeBytes > provider.config.MaximumArtifactBytes {
			return nil, ErrMeasuredInputPlan
		}
		source, err := provider.source(runtime.pin.URI, runtime.pin.SizeBytes, pinPolicy)
		if err != nil || runtime.cache == nil {
			return nil, ErrMeasuredInputPlan
		}
		defer closeMeasuredDownloadSource(source)
		downloads = append(downloads, measuredDownload{runtime.cache, source})
	}
	objects := []*p.ObjectDownload{job.Artifact}
	for _, dependency := range job.Dependencies {
		objects = append(objects, dependency.Object)
	}
	var dependencyBytes int64
	for index, object := range objects {
		if object == nil || object.SizeBytes <= 0 || object.SizeBytes > provider.config.MaximumArtifactBytes || provider.config.ArtifactCache == nil {
			return nil, ErrMeasuredInputPlan
		}
		if index > 0 {
			if object.SizeBytes > provider.config.MaximumDependencyBytes-dependencyBytes {
				return nil, ErrMeasuredInputPlan
			}
			dependencyBytes += object.SizeBytes
		}
		source, err := provider.source(object.Uri, object.SizeBytes, provider.inputPolicy)
		if err != nil {
			return nil, ErrMeasuredInputPlan
		}
		defer closeMeasuredDownloadSource(source)
		downloads = append(downloads, measuredDownload{provider.config.ArtifactCache, source})
	}
	derived, err := provider.config.RuntimeSource.DeriveMeasuredInputPlan(job, manifest, uint64(provider.config.MaximumPreparationBytes))
	if err != nil {
		return nil, ErrMeasuredInputPlan
	}
	probe := derived.ProbePlan()
	downloads = append(downloads, measuredDownload{provider.config.ArtifactCache, artifact.SourceFunc(func(ctx context.Context, out io.Writer) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, err := io.Copy(out, bytes.NewReader(probe))
		return err
	})})
	owned, err := acquireMeasuredDownloads(ctx, raw, identities, downloads)
	if err == nil {
		owned.probePlan = bytes.Clone(probe)
	}
	return owned, err
}

// Provider.source creates a private transport for each policy-constrained
// source. Do not retain idle download connections after this preparation.
func closeMeasuredDownloadSource(source artifact.Source) {
	if source, ok := source.(artifact.HTTPSource); ok && source.Client != nil {
		source.Client.CloseIdleConnections()
	}
}

// This helper handles bytes and ownership only. Its caller must derive the
// signed identities and constrain all download sources before entering it.
func acquireMeasuredDownloads(ctx context.Context, raw []byte, identities []MeasuredInputIdentity, downloads []measuredDownload) (_ *MeasuredInputs, result error) {
	if ctx == nil || ctx.Err() != nil || len(downloads) == 0 || len(downloads) != len(identities) {
		return nil, ErrMeasuredInputPlan
	}
	owned := &MeasuredInputs{request: bytes.Clone(raw)}
	owned.preparationDeadline, _ = ctx.Deadline()
	defer func() {
		if result != nil {
			_ = owned.Close()
		}
	}()
	for i, download := range downloads {
		identity := identities[i]
		if download.cache == nil || identity.SizeBytes == 0 || identity.SizeBytes > 64<<30 {
			return nil, ErrMeasuredInputPlan
		}
		entry, err := download.cache.AcquireExact(ctx, artifact.Digest(identity.SHA256), int64(identity.SizeBytes), download.source)
		if err != nil {
			return nil, ErrMeasuredInputPlan
		}
		file, err := entry.OpenDescriptor(ctx)
		if err != nil {
			return nil, ErrMeasuredInputPlan
		}
		owned.files = append(owned.files, file)
	}
	if ctx.Err() != nil {
		return nil, ErrMeasuredInputPlan
	}
	return owned, nil
}

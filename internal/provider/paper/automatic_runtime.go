package paper

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bwmp-dev/provenance-runner/internal/localjob"
	runnerv1 "github.com/bwmp-dev/provenance/gen/proto/provenance/runner/v1"
)

const runtimeDomain = "provenance.paper-runtime/v1\n"

type SignedRuntime struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}
type RuntimeSource struct {
	Origin    string
	PublicKey ed25519.PublicKey
	Client    *http.Client
}

func NewRuntimeSource(origin, publicHex string) (*RuntimeSource, error) {
	u, err := url.Parse(origin)
	key, e := hex.DecodeString(publicHex)
	if err != nil || e != nil || len(key) != ed25519.PublicKeySize || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("automatic Paper runtime origin or key invalid")
	}
	return &RuntimeSource{Origin: strings.TrimRight(origin, "/"), PublicKey: key, Client: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func runtimeID(game string, build uint32, sha, distribution, java string) string {
	value := fmt.Sprintf("%s%s\x00%d\x00%s\x00%s\x00%s\x00linux\x00amd64", runtimeDomain, game, build, sha, distribution, java)
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
func (s *RuntimeSource) verify(m SignedRuntime) (resolvedCatalog, error) {
	if len(m.Payload) == 0 || len(m.Payload) > 65536 || len(s.PublicKey) != ed25519.PublicKeySize || !ed25519.Verify(s.PublicKey, append([]byte(runtimeDomain), m.Payload...), m.Signature) {
		return resolvedCatalog{}, errors.New("runtime signature invalid")
	}
	var payload struct {
		RuntimeID string          `json:"runtimeId"`
		Catalog   json.RawMessage `json:"catalog"`
	}
	d := json.NewDecoder(bytes.NewReader(m.Payload))
	d.DisallowUnknownFields()
	if d.Decode(&payload) != nil || d.Decode(new(any)) != io.EOF {
		return resolvedCatalog{}, errors.New("runtime manifest invalid")
	}
	var c Catalog
	if err := decodeCatalogJSON(payload.Catalog, &c); err != nil {
		return resolvedCatalog{}, err
	}
	if err := ValidateOperatorCatalog(c, true); err != nil {
		return resolvedCatalog{}, err
	}
	id := runtimeID(c.Paper.GameVersion, c.Paper.Build, c.Paper.Artifact.SHA256, c.Java.Distribution, c.Java.Version)
	if id != payload.RuntimeID || c.EnvironmentID != "paper-runtime-"+id {
		return resolvedCatalog{}, errors.New("runtime identity invalid")
	}
	for _, p := range []ArtifactPin{c.Paper.Artifact, c.Java.Artifact, c.Probe, c.PreparedRuntime.Artifact} {
		if p.URI != s.Origin+"/v1/paper-runtime-assets/"+p.SHA256+"/"+p.Filename {
			return resolvedCatalog{}, errors.New("runtime asset authority invalid")
		}
	}
	return validateCatalog(c)
}

func (s *RuntimeSource) fetch(e *runnerv1.ResolvedEnvironment) (SignedRuntime, resolvedCatalog, error) {
	if s.Client == nil {
		return SignedRuntime{}, resolvedCatalog{}, errors.New("runtime HTTP client unavailable")
	}
	if e == nil {
		return SignedRuntime{}, resolvedCatalog{}, errors.New("runtime environment missing")
	}
	digest, err := sha256Digest("server_binary", e.GetServerBinary())
	if err != nil {
		return SignedRuntime{}, resolvedCatalog{}, err
	}
	id := runtimeID(e.GetGameVersion(), e.GetServerBuild(), digest, e.GetJavaDistribution(), e.GetJavaVersion())
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.Origin+"/v1/paper-runtimes/"+id, nil)
	if err != nil {
		return SignedRuntime{}, resolvedCatalog{}, err
	}
	// Runtime manifests are public and signed. No runner or updater credential is
	// ever sent to this endpoint or to the public upstream artifact mirror.
	client := *s.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		return SignedRuntime{}, resolvedCatalog{}, errors.New("runtime manifest unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return SignedRuntime{}, resolvedCatalog{}, errors.New("runtime manifest unavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 100001))
	if err != nil || len(raw) > 100000 {
		return SignedRuntime{}, resolvedCatalog{}, errors.New("runtime manifest exceeds bound")
	}
	var m SignedRuntime
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || d.Decode(new(any)) != io.EOF {
		return m, resolvedCatalog{}, errors.New("runtime envelope invalid")
	}
	c, err := s.verify(m)
	if err != nil {
		return m, c, err
	}
	p := &Provider{catalogs: map[string]resolvedCatalog{c.EnvironmentID: c}}
	_, err = p.catalogForRemoteEnvironment(e)
	return m, c, err
}

func (p *Provider) adaptAutomaticJob(spec *runnerv1.JobSpecification) (localjob.Job, error) {
	manifest, c, err := p.config.RuntimeSource.fetch(spec.GetEnvironment())
	if err != nil {
		return localjob.Job{}, err
	}
	copyProvider := *p
	copyProvider.config = p.config
	copyProvider.config.RuntimeSource = nil
	copyProvider.catalogs = map[string]resolvedCatalog{c.EnvironmentID: c}
	job, err := copyProvider.AdaptJob(spec)
	if err != nil {
		return job, err
	}
	var config configuration
	if err = json.Unmarshal(job.Environment, &config); err != nil {
		return job, err
	}
	config.RuntimeManifest = &manifest
	job.Environment, err = json.Marshal(config)
	if err != nil {
		return job, err
	}
	if len(job.Environment) > maximumNormalizedConfigurationBytes {
		return localjob.Job{}, errors.New("materialized runtime environment exceeds bound")
	}
	return job, job.Validate()
}

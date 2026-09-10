package paper

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
)

const MaximumCatalogJSONBytes = 256 << 10
const MaximumOperatorCatalogs = 32

var catalogSegment = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,199}$`)
var javaVersionPattern = regexp.MustCompile(`^[1-9][0-9]*(?:\.[0-9]+){0,3}(?:\+[0-9]+)?$`)
var gameVersionPattern = regexp.MustCompile(`^[1-9][0-9]*\.[0-9]+(?:\.[0-9]+)?$`)

// DecodeOperatorCatalogs accepts only complete operator-approved immutable pins.
// Jobs never extend this catalog or select download URLs.
func DecodeOperatorCatalogs(raw []byte) ([]Catalog, error) {
	var catalogs []Catalog
	if err := decodeCatalogJSON(raw, &catalogs); err != nil {
		return nil, err
	}
	if len(catalogs) < 1 || len(catalogs) > MaximumOperatorCatalogs {
		return nil, errors.New("catalog array must contain between 1 and 32 entries")
	}
	ids, identities, runtimes := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, c := range catalogs {
		if err := ValidateOperatorCatalog(c, true); err != nil {
			return nil, err
		}
		identity := catalogRemoteIdentity(c)
		if ids[c.EnvironmentID] || identities[identity] || runtimes[c.PreparedRuntime.Artifact.SHA256] {
			return nil, errors.New("catalog contains duplicate environment, resolved identity, or prepared-runtime digest")
		}
		ids[c.EnvironmentID], identities[identity], runtimes[c.PreparedRuntime.Artifact.SHA256] = true, true, true
	}
	return catalogs, nil
}

// DecodePreparationCatalog allows the prepared-runtime pin to be omitted: it is
// the output of preparation. Paper, Java and the trusted probe remain pinned.
func DecodePreparationCatalog(raw []byte) (Catalog, error) {
	var c Catalog
	if err := decodeCatalogJSON(raw, &c); err != nil {
		return c, err
	}
	return c, ValidateOperatorCatalog(c, false)
}

func ValidateOperatorCatalog(c Catalog, requireRuntime bool) error {
	if !catalogSegment.MatchString(c.EnvironmentID) || !gameVersionPattern.MatchString(c.Paper.GameVersion) || c.Paper.Build == 0 {
		return errors.New("catalog Paper identity is invalid")
	}
	for _, s := range []string{c.Java.Distribution, c.Java.Version, c.Java.ArchiveRoot} {
		if !catalogSegment.MatchString(s) {
			return errors.New("catalog Java identity is invalid")
		}
	}
	if !javaVersionPattern.MatchString(c.Java.Version) {
		return errors.New("catalog Java version must be an exact numeric release")
	}
	if !acceptedProbe(c) {
		return errors.New("catalog must use the accepted immutable Paper probe")
	}
	if !requireRuntime && c.PreparedRuntime == (ArchivePin{}) {
		c.PreparedRuntime = ArchivePin{Artifact: c.Paper.Artifact, MaximumExpandedBytes: 1}
	}
	_, err := validateCatalog(c)
	return err
}

func decodeCatalogJSON(raw []byte, result any) error {
	if len(raw) == 0 || len(raw) > MaximumCatalogJSONBytes {
		return errors.New("catalog JSON must be between 1 and 262144 bytes")
	}
	// Token validation rejects duplicate and case-aliased keys before Go's JSON
	// struct decoder can silently override an earlier value.
	d := json.NewDecoder(bytes.NewReader(raw))
	if err := validateJSONValue(d, 0); err != nil {
		return err
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return errors.New("catalog JSON must contain exactly one value")
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(result); err != nil {
		return errors.New("catalog JSON has an invalid schema")
	}
	return nil
}
func validateJSONValue(d *json.Decoder, depth int) error {
	if depth > 16 {
		return errors.New("catalog JSON nesting exceeds schema limits")
	}
	token, err := d.Token()
	if err != nil {
		return errors.New("invalid catalog JSON")
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		keys := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return errors.New("invalid catalog JSON object")
			}
			s, ok := key.(string)
			if !ok || keys[s] {
				return errors.New("duplicate catalog JSON key")
			}
			switch s {
			case "uri", "sha256", "filename", "sizeBytes", "environmentId", "paper", "gameVersion", "build", "artifact", "java", "distribution", "version", "os", "architecture", "archiveRoot", "maximumExpandedBytes", "probeVersion", "probeSourceCommit", "probe", "preparedRuntime":
			default:
				return errors.New("catalog JSON keys must use canonical schema names")
			}

			keys[s] = true
			if err := validateJSONValue(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := validateJSONValue(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected catalog JSON delimiter")
	}
	_, err = d.Token()
	return err
}

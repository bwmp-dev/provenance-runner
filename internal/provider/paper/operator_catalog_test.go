package paper

import (
	"encoding/json"
	"strings"
	"testing"
)

func operatorFixture() Catalog {
	c := AlphaCatalog()
	c.EnvironmentID = "paper-1.21.11-42-java-25"
	c.Paper.GameVersion = "1.21.11"
	c.Paper.Build = 42
	c.Java.Version = "25.0.2+10"
	c.Probe.URI = "https://artifacts.example/probe.jar"
	c.PreparedRuntime = ArchivePin{Artifact: ArtifactPin{URI: "https://artifacts.example/runtime.tar.gz", Filename: "runtime.tar.gz", SHA256: strings.Repeat("a", 64), SizeBytes: 100}, MaximumExpandedBytes: 1000}
	return c
}
func TestOperatorCatalogArbitraryVersionAndSubset(t *testing.T) {
	c := operatorFixture()
	raw, _ := json.Marshal([]Catalog{c})
	got, err := DecodeOperatorCatalogs(raw)
	if err != nil || len(got) != 1 || got[0] != c {
		t.Fatalf("decode = %v, %v", got, err)
	}
	for _, field := range []string{`"environmentId"`, `"sha256"`, `"os"`, `"preparedRuntime"`} {
		if !strings.Contains(string(raw), field) {
			t.Fatalf("missing stable field %s", field)
		}
	}
}
func TestOperatorCatalogRejectsTampering(t *testing.T) {
	tests := map[string]func(*Catalog){
		"probe hash":       func(c *Catalog) { c.Probe.SHA256 = strings.Repeat("b", 64) },
		"probe source":     func(c *Catalog) { c.ProbeSourceCommit = strings.Repeat("b", 40) },
		"version path":     func(c *Catalog) { c.Paper.GameVersion = "../../escape" },
		"environment path": func(c *Catalog) { c.EnvironmentID = "../escape" },
		"java path":        func(c *Catalog) { c.Java.ArchiveRoot = "../java" },
		"filename path":    func(c *Catalog) { c.Paper.Artifact.Filename = ".." },
		"floating Java":    func(c *Catalog) { c.Java.Version = "latest" },
		"java hash":        func(c *Catalog) { c.Java.Artifact.SHA256 = "bad" },
		"http":             func(c *Catalog) { c.Paper.Artifact.URI = "http://example.org/paper.jar" },
		"missing runtime":  func(c *Catalog) { c.PreparedRuntime = ArchivePin{} },
		"size bound":       func(c *Catalog) { c.Java.Artifact.SizeBytes = 1<<30 + 1 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			c := operatorFixture()
			mutate(&c)
			raw, _ := json.Marshal([]Catalog{c})
			if _, err := DecodeOperatorCatalogs(raw); err == nil {
				t.Fatal("accepted invalid catalog")
			}
		})
	}
}
func TestOperatorCatalogJSONBoundsAndDuplicates(t *testing.T) {
	c := operatorFixture()
	raw, _ := json.Marshal([]Catalog{c})
	duplicate, _ := json.Marshal([]Catalog{c, c})
	many := make([]Catalog, 33)
	manyRaw, _ := json.Marshal(many)
	for _, bad := range [][]byte{[]byte("[]"), []byte("null"), duplicate, manyRaw, []byte(strings.Repeat(" ", MaximumCatalogJSONBytes+1)), append(append([]byte{}, raw...), []byte(" []")...), []byte(strings.Replace(string(raw), `"environmentId":`, `"EnvironmentId":`, 1)), []byte(strings.Replace(string(raw), `"environmentId":`, `"environmentId":"duplicate","environmentId":`, 1)), []byte(strings.Replace(string(raw), `"environmentId":`, `"environmentid":`, 1))} {
		if _, err := DecodeOperatorCatalogs(bad); err == nil {
			t.Fatal("accepted invalid JSON")
		}
	}
}
func TestPreparationCatalogAllowsMissingOutputPin(t *testing.T) {
	c := operatorFixture()
	c.PreparedRuntime = ArchivePin{}
	raw, _ := json.Marshal(c)
	if _, err := DecodePreparationCatalog(raw); err != nil {
		t.Fatal(err)
	}
	c.Paper.Artifact.SHA256 = "bad"
	raw, _ = json.Marshal(c)
	if _, err := DecodePreparationCatalog(raw); err == nil {
		t.Fatal("accepted tampered input pin")
	}
}

func TestArbitraryCatalogRemoteSelectionRetainsExactPins(t *testing.T) {
	c := operatorFixture()
	resolved, err := validateCatalog(c)
	if err != nil {
		t.Fatal(err)
	}
	provider := &Provider{catalogs: map[string]resolvedCatalog{c.EnvironmentID: resolved}}
	environment := exactRemoteEnvironment(t, resolved)
	if _, err := provider.catalogForRemoteEnvironment(environment); err != nil {
		t.Fatal(err)
	}
	environment.JavaVersion = "21.0.8+9"
	if _, err := provider.catalogForRemoteEnvironment(environment); err == nil {
		t.Fatal("accepted different Java")
	}
	environment = exactRemoteEnvironment(t, resolved)
	environment.ServerBinary.Value[0] ^= 0xff
	if _, err := provider.catalogForRemoteEnvironment(environment); err == nil {
		t.Fatal("accepted different Paper digest")
	}
}

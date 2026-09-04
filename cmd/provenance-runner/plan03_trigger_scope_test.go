package main

import (
	"bufio"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const runnerModule = "github.com/bwmp-dev/provenance-runner"

var plan03RemoteOnlyPackages = map[string]map[string]bool{
	runnerModule + "/internal/buildinfo":      {"runConnect": true},
	runnerModule + "/internal/enrollment":     {"runEnroll": true},
	runnerModule + "/internal/gatewayclient":  {"runConnect": true},
	runnerModule + "/internal/runneridentity": {},
}

func TestPlan03RemoteOnlyPackagesStayOutsideLocalExecution(t *testing.T) {
	t.Parallel()

	repositoryRoot := plan03RepositoryRoot(t)
	assertPlan03WorkflowExclusions(t, repositoryRoot)
	assertCoveredInternalPackagesDoNotImportRemoteOnly(t, repositoryRoot)
	assertCommandUsesRemoteOnlyPackagesInAllowedFunctions(t, repositoryRoot)
}

func plan03RepositoryRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve trigger-scope test path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}

func assertPlan03WorkflowExclusions(t *testing.T, repositoryRoot string) {
	t.Helper()
	workflowPath := filepath.Join(repositoryRoot, ".github", "workflows", "plan03-acceptance.yml")
	workflow, err := os.Open(workflowPath)
	if err != nil {
		t.Fatalf("open Plan 03 workflow: %v", err)
	}
	defer workflow.Close()

	want := remoteOnlyDirectories()
	var got []string
	scanner := bufio.NewScanner(workflow)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		const prefix = `- "!internal/`
		const suffix = `/**"`
		if strings.HasPrefix(line, prefix) && strings.HasSuffix(line, suffix) {
			got = append(got, strings.TrimSuffix(strings.TrimPrefix(line, prefix), suffix))
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read Plan 03 workflow: %v", err)
	}
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Plan 03 remote-only workflow exclusions = %v, want %v", got, want)
	}
}

func remoteOnlyDirectories() []string {
	directories := make([]string, 0, len(plan03RemoteOnlyPackages))
	for importPath := range plan03RemoteOnlyPackages {
		directories = append(directories, strings.TrimPrefix(importPath, runnerModule+"/internal/"))
	}
	sort.Strings(directories)
	return directories
}

func assertCoveredInternalPackagesDoNotImportRemoteOnly(t *testing.T, repositoryRoot string) {
	t.Helper()
	internalRoot := filepath.Join(repositoryRoot, "internal")
	remoteDirectories := make(map[string]bool)
	for _, directory := range remoteOnlyDirectories() {
		remoteDirectories[directory] = true
	}

	err := filepath.WalkDir(internalRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != internalRoot && remoteDirectories[entry.Name()] && filepath.Dir(path) == internalRoot {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return err
			}
			if _, excluded := plan03RemoteOnlyRoot(importPath); excluded {
				relative, relErr := filepath.Rel(repositoryRoot, path)
				if relErr != nil {
					return relErr
				}
				t.Errorf("covered package %s imports Plan 03 remote-only package %s", relative, importPath)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("inspect covered internal packages: %v", err)
	}
}

func assertCommandUsesRemoteOnlyPackagesInAllowedFunctions(t *testing.T, repositoryRoot string) {
	t.Helper()
	commandRoot := filepath.Join(repositoryRoot, "cmd", "provenance-runner")
	entries, err := os.ReadDir(commandRoot)
	if err != nil {
		t.Fatalf("read runner command: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".go" || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(commandRoot, entry.Name())
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", entry.Name(), err)
		}
		aliases := remoteOnlyImportAliases(t, file)
		for _, declaration := range file.Decls {
			functionName := "<package scope>"
			if function, ok := declaration.(*ast.FuncDecl); ok {
				functionName = function.Name.Name
			}
			ast.Inspect(declaration, func(node ast.Node) bool {
				selector, ok := node.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				identifier, ok := selector.X.(*ast.Ident)
				if !ok {
					return true
				}
				importPath, excluded := aliases[identifier.Name]
				if excluded && !plan03RemoteOnlyPackages[importPath][functionName] {
					t.Errorf("%s uses Plan 03 remote-only package %s in %s", entry.Name(), importPath, functionName)
				}
				return true
			})
		}
	}
}

func remoteOnlyImportAliases(t *testing.T, file *ast.File) map[string]string {
	t.Helper()
	aliases := make(map[string]string)
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			t.Fatalf("decode import path: %v", err)
		}
		remoteRoot, excluded := plan03RemoteOnlyRoot(importPath)
		if !excluded {
			continue
		}
		alias := filepath.Base(importPath)
		if spec.Name != nil {
			alias = spec.Name.Name
			if alias == "." || alias == "_" {
				t.Fatalf("Plan 03 remote-only package %s uses unsupported import alias %q", importPath, alias)
			}
		}
		aliases[alias] = remoteRoot
	}
	return aliases
}

func plan03RemoteOnlyRoot(importPath string) (string, bool) {
	for remoteRoot := range plan03RemoteOnlyPackages {
		if importPath == remoteRoot || strings.HasPrefix(importPath, remoteRoot+"/") {
			return remoteRoot, true
		}
	}
	return "", false
}

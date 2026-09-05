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

const (
	sameRepositoryPullRequestGuard = "if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository"
	selfHostedLinuxX64             = "runs-on: [self-hosted, linux, x64]"
	privilegedGVisorGroup          = `group: "${{ github.repository }}-privileged-gvisor"`
)

var plan03RemoteOnlyPackages = map[string]map[string]bool{
	runnerModule + "/internal/buildinfo":      {"runConnect": true},
	runnerModule + "/internal/enrollment":     {"runEnroll": true},
	runnerModule + "/internal/gatewayclient":  {"runConnect": true},
	runnerModule + "/internal/runneridentity": {},
}

var plan03RemoteOnlyCommandFunctions = map[string]map[string]map[string]bool{
	"provenance-runner": plan03RemoteOnlyPackages,
}

func TestPlan03RemoteOnlyPackagesStayOutsideLocalExecution(t *testing.T) {
	t.Parallel()

	repositoryRoot := plan03RepositoryRoot(t)
	assertPlan03WorkflowTriggers(t, repositoryRoot)
	assertNormalCITriggers(t, repositoryRoot)
	assertSelfHostedJobPolicy(t, repositoryRoot)
	assertPlan03WorkflowExclusions(t, repositoryRoot)
	assertCoveredInternalPackagesDoNotImportRemoteOnly(t, repositoryRoot)
	assertCommandUsesRemoteOnlyPackagesInAllowedFunctions(t, repositoryRoot)
}

func assertPlan03WorkflowTriggers(t *testing.T, repositoryRoot string) {
	t.Helper()
	workflowPath := filepath.Join(repositoryRoot, ".github", "workflows", "plan03-acceptance.yml")
	workflow, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatalf("open Plan 03 workflow: %v", err)
	}
	pullRequest, push, workflowDispatch := topLevelWorkflowTriggers(t, workflow)
	if !pullRequest || push || !workflowDispatch {
		t.Fatalf("Plan 03 triggers: pull_request=%t push=%t workflow_dispatch=%t", pullRequest, push, workflowDispatch)
	}
	if !strings.Contains(string(workflow), selfHostedLinuxX64) {
		t.Fatal("Plan 03 gate must run on the self-hosted Linux x64 pool")
	}
}

func assertNormalCITriggers(t *testing.T, repositoryRoot string) {
	t.Helper()
	workflowPath := filepath.Join(repositoryRoot, ".github", "workflows", "ci.yml")
	workflow, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatalf("open normal CI workflow: %v", err)
	}
	pullRequest, push, workflowDispatch := topLevelWorkflowTriggers(t, workflow)
	if !pullRequest || !push || workflowDispatch {
		t.Fatalf("normal CI triggers: pull_request=%t push=%t workflow_dispatch=%t", pullRequest, push, workflowDispatch)
	}
	if !strings.Contains(string(workflow), "push:\n    branches:\n      - main") {
		t.Fatal("normal CI must run automatically on pushes to main")
	}
}

func assertSelfHostedJobPolicy(t *testing.T, repositoryRoot string) {
	t.Helper()
	ci := readPlan03ContractFile(t, filepath.Join(repositoryRoot, ".github", "workflows", "ci.yml"))
	ciJobs := workflowJobBlocks(t, ci)
	if len(ciJobs) != 3 {
		t.Fatalf("normal CI job set = %v", sortedKeys(ciJobs))
	}
	for _, name := range []string{"test", "gvisor-smoke", "systemd-user-smoke"} {
		job, ok := ciJobs[name]
		if !ok {
			t.Fatalf("normal CI lacks %q job", name)
		}
		if !strings.Contains(job, sameRepositoryPullRequestGuard) || !strings.Contains(job, selfHostedLinuxX64) {
			t.Fatalf("normal CI job %q is not same-repository-only on self-hosted Linux x64", name)
		}
	}
	if strings.Contains(ciJobs["test"], "concurrency:") {
		t.Fatal("ordinary test job must remain available for parallel execution")
	}
	assertPrivilegedGVisorConcurrency(t, "short gVisor smoke", ciJobs["gvisor-smoke"])

	plan03 := readPlan03ContractFile(t, filepath.Join(repositoryRoot, ".github", "workflows", "plan03-acceptance.yml"))
	plan03Jobs := workflowJobBlocks(t, plan03)
	if len(plan03Jobs) != 1 || plan03Jobs["paper-gvisor-exit-gate"] == "" {
		t.Fatalf("Plan 03 job set = %v", sortedKeys(plan03Jobs))
	}
	gate := plan03Jobs["paper-gvisor-exit-gate"]
	if !strings.Contains(gate, sameRepositoryPullRequestGuard) || !strings.Contains(gate, selfHostedLinuxX64) {
		t.Fatal("Plan 03 gate is not same-repository-only on self-hosted Linux x64")
	}
	assertPrivilegedGVisorConcurrency(t, "Plan 03 gate", gate)
}

func assertPrivilegedGVisorConcurrency(t *testing.T, name, job string) {
	t.Helper()
	if !strings.Contains(job, "concurrency:\n") || !strings.Contains(job, privilegedGVisorGroup) ||
		!strings.Contains(job, "cancel-in-progress: false") || !strings.Contains(job, "queue: max") {
		t.Fatalf("%s lacks the shared non-cancelling privileged-gVisor concurrency policy", name)
	}
}

func readPlan03ContractFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read workflow %s: %v", path, err)
	}
	return string(data)
}

func workflowJobBlocks(t *testing.T, workflow string) map[string]string {
	t.Helper()
	jobs := make(map[string]string)
	var current string
	var block strings.Builder
	inJobs := false
	flush := func() {
		if current != "" {
			jobs[current] = block.String()
			block.Reset()
		}
	}
	scanner := bufio.NewScanner(strings.NewReader(workflow))
	for scanner.Scan() {
		rawLine := scanner.Text()
		line := strings.TrimSpace(rawLine)
		indent := len(rawLine) - len(strings.TrimLeft(rawLine, " \t"))
		if !inJobs {
			if line == "jobs:" && indent == 0 {
				inJobs = true
			}
			continue
		}
		if indent == 0 && line != "" && !strings.HasPrefix(line, "#") {
			break
		}
		if indent == 2 && strings.HasSuffix(line, ":") && !strings.HasPrefix(line, "#") {
			flush()
			current = strings.TrimSuffix(line, ":")
		}
		if current != "" {
			block.WriteString(rawLine)
			block.WriteByte('\n')
		}
	}
	flush()
	if err := scanner.Err(); err != nil {
		t.Fatalf("read workflow jobs: %v", err)
	}
	return jobs
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func topLevelWorkflowTriggers(t *testing.T, workflow []byte) (pullRequest, push, workflowDispatch bool) {
	t.Helper()
	scanner := bufio.NewScanner(strings.NewReader(string(workflow)))
	inOn := false
	for scanner.Scan() {
		rawLine := scanner.Text()
		line := strings.TrimSpace(rawLine)
		indent := len(rawLine) - len(strings.TrimLeft(rawLine, " \t"))
		if !inOn {
			if line == "on:" && indent == 0 {
				inOn = true
			}
			continue
		}
		if indent == 0 && line != "" && !strings.HasPrefix(line, "#") {
			break
		}
		if indent != 2 {
			continue
		}
		switch line {
		case "pull_request:":
			pullRequest = true
		case "push:":
			push = true
		case "workflow_dispatch:":
			workflowDispatch = true
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read workflow triggers: %v", err)
	}
	return pullRequest, push, workflowDispatch
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
	workflow, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatalf("open Plan 03 workflow: %v", err)
	}

	want := remoteOnlyDirectories()
	var got []string
	var paths []string
	scanner := bufio.NewScanner(strings.NewReader(string(workflow)))
	inPullRequest := false
	inPaths := false
	for scanner.Scan() {
		rawLine := scanner.Text()
		line := strings.TrimSpace(rawLine)
		indent := len(rawLine) - len(strings.TrimLeft(rawLine, " \t"))
		if line == "pull_request:" && indent == 2 {
			inPullRequest = true
			continue
		}
		if inPullRequest && line == "paths:" && indent == 4 {
			inPaths = true
			continue
		}
		if inPaths && indent <= 4 && line != "" && !strings.HasPrefix(line, "#") {
			break
		}
		if !inPaths || !strings.HasPrefix(line, `- "`) || !strings.HasSuffix(line, `"`) {
			continue
		}
		path := strings.TrimSuffix(strings.TrimPrefix(line, `- "`), `"`)
		paths = append(paths, path)
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
	requiredPaths := []string{
		".github/workflows/plan03-acceptance.yml",
		"cmd/**",
		"internal/**",
		"scripts/plan03-acceptance.sh",
		"testdata/plan03/**",
	}
	pathIndexes := make(map[string]int, len(paths))
	for index, path := range paths {
		if _, duplicate := pathIndexes[path]; duplicate {
			t.Fatalf("Plan 03 pull-request path %q appears more than once", path)
		}
		pathIndexes[path] = index
	}
	for _, requiredPath := range requiredPaths {
		if _, present := pathIndexes[requiredPath]; !present {
			t.Errorf("Plan 03 pull-request paths do not include %q", requiredPath)
		}
	}
	internalIndex, present := pathIndexes["internal/**"]
	if !present {
		return
	}
	for _, directory := range want {
		exclusion := "!internal/" + directory + "/**"
		if exclusionIndex, present := pathIndexes[exclusion]; !present || exclusionIndex <= internalIndex {
			t.Errorf("Plan 03 exclusion %q must appear after internal/**", exclusion)
		}
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
	commandsRoot := filepath.Join(repositoryRoot, "cmd")
	commands, err := os.ReadDir(commandsRoot)
	if err != nil {
		t.Fatalf("read commands: %v", err)
	}
	for _, command := range commands {
		if !command.IsDir() {
			continue
		}
		commandName := command.Name()
		commandRoot := filepath.Join(commandsRoot, commandName)
		entries, err := os.ReadDir(commandRoot)
		if err != nil {
			t.Fatalf("read command %s: %v", commandName, err)
		}
		allowedFunctions := plan03RemoteOnlyCommandFunctions[commandName]
		for _, entry := range entries {
			if entry.IsDir() || filepath.Ext(entry.Name()) != ".go" || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(commandRoot, entry.Name())
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				t.Fatalf("parse %s/%s: %v", commandName, entry.Name(), err)
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
					if excluded && !allowedFunctions[importPath][functionName] {
						t.Errorf("%s/%s uses Plan 03 remote-only package %s in %s", commandName, entry.Name(), importPath, functionName)
					}
					return true
				})
			}
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

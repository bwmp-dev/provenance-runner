package main

import (
	"bufio"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const runnerModule = "github.com/bwmp-dev/provenance-runner"

const (
	selfHostedLinuxX64    = "runs-on: [self-hosted, linux, x64]"
	privilegedGVisorGroup = `group: "${{ github.repository }}-privileged-gvisor"`
	systemdUserSmokeGroup = `group: "${{ github.repository }}-systemd-user-smoke"`
)

var plan03RemoteOnlyPackages = map[string]map[string]bool{
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
	assertNoPublicPullRequestWorkflows(t, repositoryRoot)
	assertPlan03WorkflowTriggers(t, repositoryRoot)
	assertNormalCITriggers(t, repositoryRoot)
	assertSelfHostedJobPolicy(t, repositoryRoot)
	assertCoveredInternalPackagesDoNotImportRemoteOnly(t, repositoryRoot)
	assertCommandUsesRemoteOnlyPackagesInAllowedFunctions(t, repositoryRoot)
}

func TestTopLevelWorkflowTriggerForms(t *testing.T) {
	tests := []struct {
		name                                 string
		workflow                             string
		pullRequest, pullRequestTarget, push bool
	}{
		{
			name:        "inline sequence",
			workflow:    "name: test\non: [push, pull_request]\njobs: {}\n",
			pullRequest: true,
			push:        true,
		},
		{
			name:        "scalar",
			workflow:    "name: test\non: pull_request\njobs: {}\n",
			pullRequest: true,
		},
		{
			name:              "block pull request target",
			workflow:          "name: test\non:\n  pull_request_target:\njobs: {}\n",
			pullRequestTarget: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pullRequest, pullRequestTarget, push, workflowDispatch := topLevelWorkflowTriggers(t, []byte(test.workflow))
			if pullRequest != test.pullRequest || pullRequestTarget != test.pullRequestTarget ||
				push != test.push || workflowDispatch {
				t.Fatalf("triggers: pull_request=%t pull_request_target=%t push=%t workflow_dispatch=%t", pullRequest, pullRequestTarget, push, workflowDispatch)
			}
		})
	}
}

func assertPlan03WorkflowTriggers(t *testing.T, repositoryRoot string) {
	t.Helper()
	workflowPath := filepath.Join(repositoryRoot, ".github", "workflows", "plan03-acceptance.yml")
	workflow, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatalf("open Plan 03 workflow: %v", err)
	}
	pullRequest, pullRequestTarget, push, workflowDispatch := topLevelWorkflowTriggers(t, workflow)
	if pullRequest || pullRequestTarget || push || !workflowDispatch {
		t.Fatalf("Plan 03 triggers: pull_request=%t pull_request_target=%t push=%t workflow_dispatch=%t", pullRequest, pullRequestTarget, push, workflowDispatch)
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
	pullRequest, pullRequestTarget, push, workflowDispatch := topLevelWorkflowTriggers(t, workflow)
	if pullRequest || pullRequestTarget || !push || workflowDispatch {
		t.Fatalf("normal CI triggers: pull_request=%t pull_request_target=%t push=%t workflow_dispatch=%t", pullRequest, pullRequestTarget, push, workflowDispatch)
	}
	triggerBlock := workflowTriggerBlock(t, workflow)
	if strings.Contains(triggerBlock, "branches:") || strings.Contains(triggerBlock, "branches-ignore:") ||
		strings.Contains(triggerBlock, "paths:") || strings.Contains(triggerBlock, "paths-ignore:") {
		t.Fatal("normal CI push trigger must cover every trusted upstream branch and path")
	}
}

func assertNoPublicPullRequestWorkflows(t *testing.T, repositoryRoot string) {
	t.Helper()
	var paths []string
	for _, pattern := range []string{"*.yml", "*.yaml"} {
		matches, err := filepath.Glob(filepath.Join(repositoryRoot, ".github", "workflows", pattern))
		if err != nil {
			t.Fatalf("enumerate workflows matching %s: %v", pattern, err)
		}
		paths = append(paths, matches...)
	}
	if len(paths) == 0 {
		t.Fatal("workflow directory contains no .yml or .yaml files")
	}
	sort.Strings(paths)
	for _, path := range paths {
		workflow := readPlan03ContractFile(t, path)
		pullRequest, pullRequestTarget, _, _ := topLevelWorkflowTriggers(t, []byte(workflow))
		if pullRequest || pullRequestTarget {
			t.Errorf("public pull-request trigger can schedule workflow %s", filepath.Base(path))
		}
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
		if !strings.Contains(job, selfHostedLinuxX64) {
			t.Fatalf("normal CI job %q is not on self-hosted Linux x64", name)
		}
	}
	if strings.Contains(ciJobs["test"], "concurrency:") {
		t.Fatal("ordinary test job must remain available for parallel execution")
	}
	assertPrivilegedGVisorConcurrency(t, "short gVisor smoke", ciJobs["gvisor-smoke"])
	assertQueuedConcurrency(t, "systemd-user smoke", ciJobs["systemd-user-smoke"], systemdUserSmokeGroup)
	if strings.Contains(ci, "github.event.pull_request") {
		t.Fatal("push-only normal CI must not derive checkout or artifact identity from a pull-request event")
	}

	plan03 := readPlan03ContractFile(t, filepath.Join(repositoryRoot, ".github", "workflows", "plan03-acceptance.yml"))
	plan03Jobs := workflowJobBlocks(t, plan03)
	if len(plan03Jobs) != 1 || plan03Jobs["paper-gvisor-exit-gate"] == "" {
		t.Fatalf("Plan 03 job set = %v", sortedKeys(plan03Jobs))
	}
	gate := plan03Jobs["paper-gvisor-exit-gate"]
	if !strings.Contains(gate, selfHostedLinuxX64) {
		t.Fatal("Plan 03 gate is not on self-hosted Linux x64")
	}
	assertPrivilegedGVisorConcurrency(t, "Plan 03 gate", gate)
}

func assertPrivilegedGVisorConcurrency(t *testing.T, name, job string) {
	t.Helper()
	assertQueuedConcurrency(t, name, job, privilegedGVisorGroup)
}

func assertQueuedConcurrency(t *testing.T, name, job, group string) {
	t.Helper()
	if !strings.Contains(job, "concurrency:\n") || !strings.Contains(job, group) ||
		!strings.Contains(job, "cancel-in-progress: false") || !strings.Contains(job, "queue: max") {
		t.Fatalf("%s lacks its repository-scoped non-cancelling queued concurrency policy", name)
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

func workflowTriggerBlock(t *testing.T, workflow []byte) string {
	t.Helper()
	var block strings.Builder
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
		block.WriteString(rawLine)
		block.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read workflow trigger block: %v", err)
	}
	return block.String()
}

func topLevelWorkflowTriggers(t *testing.T, workflow []byte) (pullRequest, pullRequestTarget, push, workflowDispatch bool) {
	t.Helper()
	record := func(event string) {
		switch event {
		case "pull_request":
			pullRequest = true
		case "pull_request_target":
			pullRequestTarget = true
		case "push":
			push = true
		case "workflow_dispatch":
			workflowDispatch = true
		}
	}

	scanner := bufio.NewScanner(strings.NewReader(string(workflow)))
	inOn := false
	foundOn := false
	for scanner.Scan() {
		rawLine := scanner.Text()
		line := strings.TrimSpace(rawLine)
		indent := len(rawLine) - len(strings.TrimLeft(rawLine, " \t"))
		if !inOn {
			if indent != 0 || !strings.HasPrefix(line, "on:") {
				continue
			}
			foundOn = true
			value := strings.TrimSpace(strings.TrimPrefix(line, "on:"))
			value = strings.TrimSpace(strings.SplitN(value, " #", 2)[0])
			if value == "" || strings.HasPrefix(value, "#") {
				inOn = true
				continue
			}
			for _, event := range inlineWorkflowTriggers(t, value) {
				record(event)
			}
			break
		}
		if indent == 0 && line != "" && !strings.HasPrefix(line, "#") {
			break
		}
		if indent != 2 || line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, _, ok := strings.Cut(line, ":")
		if !ok {
			t.Fatalf("unsupported workflow trigger entry %q", line)
		}
		record(unquoteWorkflowTrigger(t, strings.TrimSpace(key)))
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read workflow triggers: %v", err)
	}
	if !foundOn {
		t.Fatal("workflow lacks a supported top-level on declaration")
	}
	return pullRequest, pullRequestTarget, push, workflowDispatch
}

func inlineWorkflowTriggers(t *testing.T, value string) []string {
	t.Helper()
	if strings.HasPrefix(value, "[") {
		if !strings.HasSuffix(value, "]") {
			t.Fatalf("unterminated inline workflow trigger sequence %q", value)
		}
		value = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(value, "["), "]"))
		if value == "" {
			t.Fatalf("empty inline workflow trigger sequence")
		}
		parts := strings.Split(value, ",")
		events := make([]string, 0, len(parts))
		for _, part := range parts {
			events = append(events, unquoteWorkflowTrigger(t, strings.TrimSpace(part)))
		}
		return events
	}
	if strings.ContainsAny(value, "{}[],") {
		t.Fatalf("unsupported inline workflow trigger declaration %q", value)
	}
	return []string{unquoteWorkflowTrigger(t, value)}
}

func unquoteWorkflowTrigger(t *testing.T, value string) string {
	t.Helper()
	if value == "" {
		t.Fatal("empty workflow trigger name")
	}
	if strings.HasPrefix(value, "'") || strings.HasSuffix(value, "'") {
		if len(value) < 2 || !strings.HasPrefix(value, "'") || !strings.HasSuffix(value, "'") {
			t.Fatalf("malformed quoted workflow trigger %q", value)
		}
		return strings.ReplaceAll(value[1:len(value)-1], "''", "'")
	}
	if strings.HasPrefix(value, `"`) || strings.HasSuffix(value, `"`) {
		unquoted, err := strconv.Unquote(value)
		if err != nil {
			t.Fatalf("malformed quoted workflow trigger %q: %v", value, err)
		}
		return unquoted
	}
	if strings.ContainsAny(value, " \t:#") {
		t.Fatalf("malformed workflow trigger name %q", value)
	}
	return value
}

func plan03RepositoryRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve trigger-scope test path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
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

//go:build linux

package gvisor

import (
	"context"
	"errors"
	"os/exec"
	"testing"
	"time"
)

func TestCompletedOutcomeDistinguishesExactExitFromInfrastructure(t *testing.T) {
	// Only trusted host shell built-ins run here, never a customer artifact.
	// Private owner construction tests classification, not sandbox retirement.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/bin/sh", "-c", "exit 7")
	command.Env = []string{"PATH=/usr/bin:/bin"}
	exitErr := command.Run()
	if _, ok := exitErr.(*exec.ExitError); !ok {
		t.Fatal("fixture exit", exitErr)
	}
	done := make(chan struct{})
	close(done)
	process := &MeasuredNetworkProcess{cmd: command, done: done, exitErr: exitErr}
	job := &measuredControllerJob{controller: &measuredController{}, session: &measuredNetworkSession{process: process}, retired: true, reason: exitErr}
	if code, infra, err := job.CompletedProcessOutcome(); err != nil || code != 7 || infra {
		t.Fatal("nonzero exit mislabeled", err)
	}
	for _, reason := range []error{context.Canceled, errors.Join(exitErr, ErrRouterOwner), &exec.ExitError{ProcessState: command.ProcessState}} {
		job.reason = reason
		if code, infra, err := job.CompletedProcessOutcome(); err != nil || code != 7 || !infra {
			t.Fatal("infrastructure error lost", err)
		}
	}
	job.retired = false
	if _, _, err := job.CompletedProcessOutcome(); err == nil {
		t.Fatal("unretired outcome")
	}
}

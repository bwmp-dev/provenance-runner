package paper

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

const maximumPreparationOutputBytes = 64 << 10

type RuntimePreparation struct {
	JavaExecutable  string
	ServerDirectory string
}

type RuntimePreparer interface {
	Prepare(context.Context, RuntimePreparation) error
}

type commandRuntimePreparer struct{}

func (commandRuntimePreparer) Prepare(ctx context.Context, preparation RuntimePreparation) error {
	if preparation.JavaExecutable == "" || preparation.ServerDirectory == "" {
		return errors.New("runtime preparation paths are required")
	}
	output := &boundedOutput{remaining: maximumPreparationOutputBytes}
	command := exec.CommandContext(ctx, preparation.JavaExecutable, "-Dhttp.agent="+DownloadUserAgent, "-Dpaperclip.patchonly=true", "-jar", "paper.jar")
	command.Dir = preparation.ServerDirectory
	command.Stdout = output
	command.Stderr = output
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		message := strings.TrimSpace(output.String())
		if message == "" {
			return fmt.Errorf("Paperclip preparation failed: %w", err)
		}
		return fmt.Errorf("Paperclip preparation failed: %w: %s", err, message)
	}
	return nil
}

type boundedOutput struct {
	content   strings.Builder
	remaining int
	truncated bool
}

func (w *boundedOutput) Write(content []byte) (int, error) {
	original := len(content)
	if len(content) > w.remaining {
		content = content[:w.remaining]
		w.truncated = true
	}
	if len(content) > 0 {
		_, _ = w.content.Write(content)
		w.remaining -= len(content)
	}
	return original, nil
}

func (w *boundedOutput) String() string {
	if !w.truncated {
		return w.content.String()
	}
	return w.content.String() + "\n[preparation output truncated]"
}

var _ io.Writer = (*boundedOutput)(nil)

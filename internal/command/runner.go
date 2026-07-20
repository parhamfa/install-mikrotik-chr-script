package command

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
	LookPath(name string) (string, error)
}

type OSRunner struct{}

func (OSRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

func (OSRunner) LookPath(name string) (string, error) {
	return exec.LookPath(name)
}

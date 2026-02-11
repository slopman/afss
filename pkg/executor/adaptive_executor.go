package executor

import (
	"context"
	"fmt"
	"os/exec"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
)

// AdaptiveExecutor executes tools with resource awareness
type AdaptiveExecutor struct {
	resourceManager *ResourceManager
	logger          *logrus.Logger
}

// NewAdaptiveExecutor creates a new adaptive executor
func NewAdaptiveExecutor(rm *ResourceManager, logger *logrus.Logger) *AdaptiveExecutor {
	return &AdaptiveExecutor{
		resourceManager: rm,
		logger:          logger,
	}
}

// ExecuteTool runs a tool with resource control and process groups
func (ae *AdaptiveExecutor) ExecuteTool(ctx context.Context, toolName string, binPath string, args []string, repoPath string) (string, error) {
	// 1. Get repository size for resource estimation
	repoSize := ae.getRepoSize(repoPath)

	// 2. Allocate resources (blocks until available)
	ae.logger.Infof("Waiting for resources to run tool: %s", toolName)
	release, err := ae.resourceManager.AllocateResources(ctx, toolName, repoSize)
	if err != nil {
		return "", fmt.Errorf("resource allocation failed: %w", err)
	}
	defer release()

	ae.logger.Infof("Starting tool: %s (%s)", toolName, binPath)

	// 3. Setup command with Process Group
	cmd := exec.CommandContext(ctx, binPath, args...)
	cmd.Dir = repoPath
	
	// Create a new process group to ensure all descendants can be killed
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	// Capture output
	var stdout, stderr []byte
	cmd.Stdout = &bytesBufferWrapper{&stdout}
	cmd.Stderr = &bytesBufferWrapper{&stderr}

	// 4. Start process
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("failed to start tool %s: %w", toolName, err)
	}

	// 5. Wait for completion or context cancellation
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-ctx.Done():
		// Context cancelled/timed out, kill the whole process group
		ae.logger.Warnf("Tool %s timed out or cancelled, killing process group", toolName)
		ae.killProcessGroup(cmd.Process.Pid)
		return string(stdout), ctx.Err()
	case err := <-done:
		if err != nil {
			return string(stdout), err
		}
	}

	return string(stdout), nil
}

// killProcessGroup kills the entire process group starting with the given PID
func (ae *AdaptiveExecutor) killProcessGroup(pid int) {
	// Send SIGTERM to the whole group (negative PID means group)
	pgid, err := syscall.Getpgid(pid)
	if err == nil {
		syscall.Kill(-pgid, syscall.SIGTERM)
		
		// Give it a moment to cleanup, then SIGKILL if still running
		time.AfterFunc(2*time.Second, func() {
			syscall.Kill(-pgid, syscall.SIGKILL)
		})
	} else {
		// Fallback to killing just the PID if pgid fails
		syscall.Kill(pid, syscall.SIGKILL)
	}
}

// getRepoSize estimates the size of the directory in MB
func (ae *AdaptiveExecutor) getRepoSize(path string) int64 {
	// Simple walking is slow for large repos, but good enough for now
	// In production, we might use a faster method or cache this
	// For now, let's assume it's small or return a fixed value if it takes too long
	return 100 // Default 100MB
}

// bytesBufferWrapper is a simple wrapper to collect output
type bytesBufferWrapper struct {
	buf *[]byte
}

func (w *bytesBufferWrapper) Write(p []byte) (n int, err error) {
	*w.buf = append(*w.buf, p...)
	return len(p), nil
}

package executor

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/security-scanner/afss-orchestrator/pkg/models"
)

func TestAdaptiveExecutor_Execute(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	rm := NewResourceManager(nil, &models.OrchestratorConfig{})
	ae := NewAdaptiveExecutor(rm, logger)

	ctx := context.Background()

	// Use 'echo' as a dummy tool
	output, err := ae.ExecuteTool(ctx, "echo", []string{"hello world"}, ".")
	if err != nil {
		t.Fatalf("ExecuteTool failed: %v", err)
	}

	if output != "hello world\n" {
		t.Errorf("Expected 'hello world\\n', got %q", output)
	}
}

func TestAdaptiveExecutor_Timeout(t *testing.T) {
	logger := logrus.New()
	rm := NewResourceManager(nil, &models.OrchestratorConfig{})
	ae := NewAdaptiveExecutor(rm, logger)

	// Use 'sleep' and a short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := ae.ExecuteTool(ctx, "sleep", []string{"2"}, ".")
	duration := time.Since(start)

	if err == nil {
		t.Error("Expected error due to timeout, got nil")
	}

	if duration > 500*time.Millisecond {
		t.Errorf("Tool took too long to return after timeout: %v", duration)
	}
}

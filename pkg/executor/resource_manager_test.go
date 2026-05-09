package executor

import (
	"context"
	"testing"
	"time"

	"github.com/security-scanner/afss-orchestrator/pkg/models"
)

func TestResourceManager_Allocate(t *testing.T) {
	config := &models.OrchestratorConfig{}
	rm := NewResourceManager(nil, config)

	// Register a tool profile
	rm.RegisterToolProfile(models.ToolResourceProfile{
		ToolName:     "test-tool",
		MemoryPeakMB: 1024,
	})

	ctx := context.Background()

	// 1. First allocation should succeed
	release, err := rm.AllocateResources(ctx, "test-tool", 0)
	if err != nil {
		t.Fatalf("Failed to allocate resources: %v", err)
	}

	// 2. Try to allocate more than total weight (total is 100, 1024MB on 8GB is ~12 weight)
	// Let's create a tool that takes 100% of resources
	rm.RegisterToolProfile(models.ToolResourceProfile{
		ToolName:     "greedy-tool",
		MemoryPeakMB: 8192,
	})

	// This should block if we try to allocate it while test-tool is running
	// But we use NewWeighted(100), and weight is calculated as (MemoryPeakMB / TotalMemoryMB) * 100
	// 8192 / 8192 * 100 = 100 weight.
	
	ctxTimeout, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()

	_, err = rm.AllocateResources(ctxTimeout, "greedy-tool", 0)
	if err == nil {
		t.Error("Expected greedy-tool allocation to fail due to timeout (blocked)")
	}

	// 3. Release first tool
	release()

	// 4. Now greedy-tool should succeed
	ctx2 := context.Background()
	release2, err := rm.AllocateResources(ctx2, "greedy-tool", 0)
	if err != nil {
		t.Fatalf("Failed to allocate resources for greedy-tool after release: %v", err)
	}
	release2()
}

func TestResourceManager_IOHeavy(t *testing.T) {
	config := &models.OrchestratorConfig{}
	rm := NewResourceManager(nil, config)

	ctx := context.Background()

	// IO-heavy tools share a semaphore with capacity 1 (see NewResourceManager).
	r1, err := rm.AllocateResources(ctx, "semgrep", 0)
	if err != nil {
		t.Fatal(err)
	}

	ctxTimeout, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()

	_, err = rm.AllocateResources(ctxTimeout, "trivy", 0)
	if err == nil {
		t.Error("Expected 2nd IO heavy tool to block while first holds the IO slot")
	}

	r1()

	r2, err := rm.AllocateResources(context.Background(), "trivy", 0)
	if err != nil {
		t.Fatalf("Second IO heavy tool should succeed after release: %v", err)
	}
	r2()
}

package executor

import (
	"context"
	"fmt"
	"sync"

	"golang.org/x/sync/semaphore"

	"github.com/security-scanner/afss-orchestrator/pkg/models"
	"github.com/security-scanner/afss-orchestrator/pkg/monitor"
)

// ResourceManager manages resource allocation for tool execution
type ResourceManager struct {
	monitor      *monitor.ResourceMonitor
	config       *models.OrchestratorConfig
	semaphore    *semaphore.Weighted
	ioSemaphore  *semaphore.Weighted
	mu           sync.RWMutex
	toolProfiles map[string]models.ToolResourceProfile
}

// NewResourceManager creates a new resource manager
func NewResourceManager(monitor *monitor.ResourceMonitor, config *models.OrchestratorConfig) *ResourceManager {
	// Total capacity is MaxParallelScans
	maxParallel := int64(config.Resources.MaxParallelScans)
	if maxParallel <= 0 {
		maxParallel = 2 // Safety default
	}

	// Max IO heavy tools default to 1 for stricter control on large repos
	maxIO := int64(1)

	return &ResourceManager{
		monitor:      monitor,
		config:       config,
		semaphore:    semaphore.NewWeighted(maxParallel),
		ioSemaphore:  semaphore.NewWeighted(maxIO),
		toolProfiles: make(map[string]models.ToolResourceProfile),
	}
}

// RegisterToolProfile registers a resource profile for a tool
func (rm *ResourceManager) RegisterToolProfile(profile models.ToolResourceProfile) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.toolProfiles[profile.ToolName] = profile
}

// AllocateResources attempts to allocate resources for a tool. Blocks until available.
func (rm *ResourceManager) AllocateResources(ctx context.Context, toolName string, repoSizeMB int64) (func(), error) {
	rm.mu.RLock()
	profile, ok := rm.toolProfiles[toolName]
	rm.mu.RUnlock()

	if !ok {
		// Use default profile if not registered
		profile = models.ToolResourceProfile{
			ToolName:     toolName,
			MemoryPeakMB: 256, // Default
		}
	}

	// Determine weight (cost) of the tool
	weight := rm.calculateWeight(profile, repoSizeMB)

	// Check absolute thresholds first (if monitor is available)
	if rm.monitor != nil {
		current := rm.monitor.GetCurrentResources()
		if current.MemoryPercent > rm.config.Resources.MemoryLimitPercent ||
			current.CPUUsedPercent > rm.config.Resources.CPULimitPercent {
			// Even if semaphore is free, don't start if system is already overloaded
			// In a real system we might want to wait here too
		}
	}

	// Acquire weighted semaphore
	if err := rm.semaphore.Acquire(ctx, weight); err != nil {
		return nil, fmt.Errorf("failed to acquire resource semaphore: %w", err)
	}

	// Handle IO heavy tools
	isIOHeavy := rm.isIOHeavy(toolName)
	if isIOHeavy {
		if err := rm.ioSemaphore.Acquire(ctx, 1); err != nil {
			rm.semaphore.Release(weight)
			return nil, fmt.Errorf("failed to acquire IO semaphore: %w", err)
		}
	}

	// Return release function
	release := func() {
		rm.semaphore.Release(weight)
		if isIOHeavy {
			rm.ioSemaphore.Release(1)
		}
	}

	return release, nil
}

// calculateWeight determines the resource cost (relative to MaxParallelScans)
func (rm *ResourceManager) calculateWeight(profile models.ToolResourceProfile, repoSizeMB int64) int64 {
	// Now weight is simplified: 1 unit per tool by default
	// If a tool is very heavy (e.g. > 1GB RAM) or repo is huge, it can take 2 units
	weight := int64(1)

	// If tool profile suggests it needs significant memory (> 2GB), take more slots
	if profile.MemoryPeakMB > 2048 {
		weight = 2
	}

	// If repository is massive, increase cost
	if repoSizeMB > 2048 {
		weight++
	}

	// Cap weight at total capacity
	maxParallel := int64(rm.config.Resources.MaxParallelScans)
	if maxParallel <= 0 {
		maxParallel = 2
	}
	if weight > maxParallel {
		weight = maxParallel
	}

	return weight
}

// isIOHeavy returns true if the tool is disk-intensive
func (rm *ResourceManager) isIOHeavy(toolName string) bool {
	// Hardcoded list for now, could be in YAML
	switch toolName {
	case "semgrep", "trivy", "owasp-dep-check", "osv-scanner":
		return true
	}
	return false
}

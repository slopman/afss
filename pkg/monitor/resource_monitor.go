package monitor

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/sirupsen/logrus"

	"github.com/security-scanner/afss-orchestrator/pkg/models"
)

// ResourceMonitor monitors system resource usage
type ResourceMonitor struct {
	systemInfo    *SystemInfo
	snapshots     []models.ResourceSnapshot
	running       bool
	snapshotMutex sync.RWMutex
	cancel        context.CancelFunc
	logger        *logrus.Logger
}

// SystemInfo holds static system information
type SystemInfo struct {
	TotalMemoryMB int
	TotalDiskMB   int
	CPUCount      int
}

// NewResourceMonitor creates a new resource monitor
func NewResourceMonitor(logger *logrus.Logger) *ResourceMonitor {
	systemInfo := &SystemInfo{}

	// Get total memory
	if vmStat, err := mem.VirtualMemory(); err == nil {
		systemInfo.TotalMemoryMB = int(vmStat.Total / 1024 / 1024)
	}

	// Get total disk space (root filesystem)
	if diskStat, err := disk.Usage("/"); err == nil {
		systemInfo.TotalDiskMB = int(diskStat.Total / 1024 / 1024)
	}

	// Get CPU count
	if cpuCount, err := cpu.Counts(true); err == nil {
		systemInfo.CPUCount = cpuCount
	}

	return &ResourceMonitor{
		systemInfo: systemInfo,
		snapshots:  make([]models.ResourceSnapshot, 0),
		logger:     logger,
	}
}

// StartMonitoring starts background resource monitoring
func (rm *ResourceMonitor) StartMonitoring(ctx context.Context, interval time.Duration) {
	rm.running = true
	ctx, cancel := context.WithCancel(ctx)
	rm.cancel = cancel

	rm.logger.Info("Starting resource monitoring", "interval", interval)

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				rm.logger.Info("Stopping resource monitoring")
				rm.running = false
				return
			case <-ticker.C:
				snapshot := rm.takeSnapshot()
				rm.addSnapshot(snapshot)
			}
		}
	}()
}

// StopMonitoring stops background monitoring
func (rm *ResourceMonitor) StopMonitoring() {
	if rm.cancel != nil {
		rm.cancel()
	}
}

// GetSystemInfo returns static system information
func (rm *ResourceMonitor) GetSystemInfo() *SystemInfo {
	return rm.systemInfo
}

// GetCurrentResources returns current resource usage
func (rm *ResourceMonitor) GetCurrentResources() models.ResourceSnapshot {
	return rm.takeSnapshot()
}

// GetResourceSnapshots returns all collected snapshots
func (rm *ResourceMonitor) GetResourceSnapshots() []models.ResourceSnapshot {
	rm.snapshotMutex.RLock()
	defer rm.snapshotMutex.RUnlock()

	snapshots := make([]models.ResourceSnapshot, len(rm.snapshots))
	copy(snapshots, rm.snapshots)
	return snapshots
}

// GetAverageResources calculates average resource usage over a time period
func (rm *ResourceMonitor) GetAverageResources(since time.Time) (models.ResourceSnapshot, error) {
	rm.snapshotMutex.RLock()
	defer rm.snapshotMutex.RUnlock()

	var relevantSnapshots []models.ResourceSnapshot
	for _, snapshot := range rm.snapshots {
		if snapshot.Timestamp.After(since) {
			relevantSnapshots = append(relevantSnapshots, snapshot)
		}
	}

	if len(relevantSnapshots) == 0 {
		return models.ResourceSnapshot{}, fmt.Errorf("no snapshots found since %v", since)
	}

	avg := models.ResourceSnapshot{
		Timestamp:     time.Now(),
		MemoryTotalMB: rm.systemInfo.TotalMemoryMB,
	}

	totalMemory := 0
	totalMemoryPercent := 0.0
	totalCPU := 0.0
	totalDiskUsed := 0
	totalDiskFree := 0

	for _, snapshot := range relevantSnapshots {
		totalMemory += snapshot.MemoryUsedMB
		totalMemoryPercent += snapshot.MemoryPercent
		totalCPU += snapshot.CPUUsedPercent
		totalDiskUsed += snapshot.DiskUsedMB
		totalDiskFree += snapshot.DiskFreeMB
	}

	count := float64(len(relevantSnapshots))
	avg.MemoryUsedMB = int(float64(totalMemory) / count)
	avg.MemoryPercent = totalMemoryPercent / count
	avg.CPUUsedPercent = totalCPU / count
	avg.DiskUsedMB = int(float64(totalDiskUsed) / count)
	avg.DiskFreeMB = int(float64(totalDiskFree) / count)

	return avg, nil
}

// CheckResourcePressure checks if system is under resource pressure
func (rm *ResourceMonitor) CheckResourcePressure(memoryThreshold, cpuThreshold float64) bool {
	current := rm.GetCurrentResources()

	return current.MemoryPercent > memoryThreshold || current.CPUUsedPercent > cpuThreshold
}

// takeSnapshot captures current resource usage
func (rm *ResourceMonitor) takeSnapshot() models.ResourceSnapshot {
	snapshot := models.ResourceSnapshot{
		Timestamp:     time.Now(),
		MemoryTotalMB: rm.systemInfo.TotalMemoryMB,
	}

	// Memory usage
	if vmStat, err := mem.VirtualMemory(); err == nil {
		snapshot.MemoryUsedMB = int(vmStat.Used / 1024 / 1024)
		snapshot.MemoryPercent = vmStat.UsedPercent
	} else {
		rm.logger.Warn("Failed to get memory stats", "error", err)
	}

	// CPU usage (average over 1 second)
	if cpuPercent, err := cpu.Percent(time.Second, false); err == nil && len(cpuPercent) > 0 {
		snapshot.CPUUsedPercent = cpuPercent[0]
	} else {
		rm.logger.Warn("Failed to get CPU stats", "error", err)
	}

	// Disk usage (root filesystem)
	if diskStat, err := disk.Usage("/"); err == nil {
		snapshot.DiskUsedMB = int(diskStat.Used / 1024 / 1024)
		snapshot.DiskFreeMB = int(diskStat.Free / 1024 / 1024)
	} else {
		rm.logger.Warn("Failed to get disk stats", "error", err)
	}

	return snapshot
}

// addSnapshot adds a snapshot to the history (with limit)
func (rm *ResourceMonitor) addSnapshot(snapshot models.ResourceSnapshot) {
	rm.snapshotMutex.Lock()
	defer rm.snapshotMutex.Unlock()

	rm.snapshots = append(rm.snapshots, snapshot)

	// Keep only last 1000 snapshots to prevent memory issues
	if len(rm.snapshots) > 1000 {
		rm.snapshots = rm.snapshots[len(rm.snapshots)-1000:]
	}
}

// IsMonitoring returns whether monitoring is currently active
func (rm *ResourceMonitor) IsMonitoring() bool {
	return rm.running
}
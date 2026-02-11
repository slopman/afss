# Resource Manager & Adaptive Execution Design

## 🎯 **ПРОБЛЕМА: ОРКЕСТРАТОР НЕ КОНТРОЛИРУЕТ РЕСУРСЫ**

Текущий оркестратор запускает все 12 инструментов одновременно без контроля:
- **CPU:** 1200% загрузка всех ядер
- **RAM:** 16GB+ с OOM kills
- **Disk:** 50GB+ временных файлов
- **System:** зависание или крах

## 🏗️ **РЕШЕНИЕ: RESOURCE MANAGER + ADAPTIVE EXECUTOR**

### **АРХИТЕКТУРА**

```
System Resources Monitor
       ↓
Resource Manager (Resource Allocation)
       ↓
Adaptive Executor (Smart Scheduling)
       ↓
Tool Runner (Controlled Execution)
       ↓
Status Tracker (Execution State)
       ↓
Results Aggregator (JSON + Status Flags)
```

## 📋 **КОМПОНЕНТЫ**

### **1. SYSTEM RESOURCES MONITOR**
**Цель:** Реальный мониторинг системных ресурсов

```go
type SystemResources struct {
    CPU struct {
        UsagePercent    float64 `json:"usage_percent"`
        Cores           int     `json:"cores"`
        LoadAverage     [3]float64 `json:"load_average"`
    } `json:"cpu"`

    Memory struct {
        Total           uint64  `json:"total_bytes"`         // Host total OR container limit
        Used            uint64  `json:"used_bytes"`
        Available       uint64  `json:"available_bytes"`
        UsagePercent    float64 `json:"usage_percent"`
        IsContainer     bool    `json:"is_container"`        // True if running in container
        CgroupLimit     uint64  `json:"cgroup_limit"`        // Container memory limit from cgroups
    } `json:"memory"`

    Disk struct {
        Total           uint64  `json:"total_bytes"`
        Used            uint64  `json:"used_bytes"`
        Available       uint64  `json:"available_bytes"`
        UsagePercent    float64 `json:"usage_percent"`
    } `json:"disk"`

    Network struct {
        BytesSent       uint64 `json:"bytes_sent"`
        BytesReceived   uint64 `json:"bytes_received"`
    } `json:"network"`

    Timestamp       time.Time `json:"timestamp"`
}

type ResourceMonitor struct {
    interval    time.Duration
    thresholds  ResourceThresholds
    history     []SystemResources
    alerts      chan ResourceAlert
}

type ResourceThresholds struct {
    CPUWarning     float64 `yaml:"cpu_warning"`      // 70%
    CPUCritical    float64 `yaml:"cpu_critical"`     // 90%
    MemWarning     float64 `yaml:"mem_warning"`      // 80%
    MemCritical    float64 `yaml:"mem_critical"`     // 95%
    DiskWarning    float64 `yaml:"disk_warning"`     // 85%
    DiskCritical   float64 `yaml:"disk_critical"`    // 95%
}
```

**Методы мониторинга:**
```go
func (rm *ResourceMonitor) Start(ctx context.Context) {
    ticker := time.NewTicker(rm.interval)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            resources := rm.collectResources()
            rm.history = append(rm.history, resources)
            rm.checkThresholds(resources)
        }
    }
}

func (rm *ResourceMonitor) collectResources() SystemResources {
    resources := SystemResources{Timestamp: time.Now()}

    // Detect if running in container
    resources.Memory.IsContainer = detectContainerEnvironment()

    // Get memory info
    if resources.Memory.IsContainer {
        // Read container limits from cgroups
        if cgroupLimit := readCgroupMemoryLimit(); cgroupLimit > 0 {
            resources.Memory.CgroupLimit = cgroupLimit
            resources.Memory.Total = cgroupLimit // Use container limit, not host total
        }
    }

    // Fallback to system info if not in container
    if resources.Memory.Total == 0 {
        resources.Memory.Total = getSystemMemoryTotal()
    }

    // ... rest of collection logic

    return resources
}

func detectContainerEnvironment() bool {
    // Check for container indicators
    if _, err := os.Stat("/.dockerenv"); err == nil {
        return true
    }
    if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
        return strings.Contains(string(data), "docker") ||
               strings.Contains(string(data), "containerd")
    }
    return false
}

func readCgroupMemoryLimit() uint64 {
    // Read from /sys/fs/cgroup/memory/memory.limit_in_bytes
    if data, err := os.ReadFile("/sys/fs/cgroup/memory/memory.limit_in_bytes"); err == nil {
        if limit, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64); err == nil {
            // Check if limit is reasonable (not unlimited)
            if limit < 1024*1024*1024*1024 { // < 1TB
                return limit
            }
        }
    }
    return 0
}
```

### **2. RESOURCE MANAGER**
**Цель:** Управление аллокацией ресурсов

```go
type ResourceManager struct {
    monitor        *ResourceMonitor
    toolProfiles   map[string]ToolResourceProfile
    semaphore      *semaphore.Weighted              // Weighted semaphore for resource management
    ioSemaphore    *semaphore.Weighted              // Separate semaphore for IO-intensive tools
    currentUsage   map[string]*ToolExecution
    allocation     ResourceAllocation
    mu             sync.RWMutex                     // For thread-safe access
}

type ToolResourceProfile struct {
    Name            string  `yaml:"name"`

    // Dynamic resource estimation (scales with repo size)
    BaseMemMB       int     `yaml:"base_mem_mb"`       // Base memory usage
    MemMultiplier   float64 `yaml:"mem_multiplier"`    // MB per MB of repo size
    BaseCPUMax      float64 `yaml:"base_cpu_max"`      // Base CPU usage %
    CPUMultiplier   float64 `yaml:"cpu_multiplier"`    // CPU % per MB of repo size

    // Static resource limits
    DiskUsageMB     int     `yaml:"disk_usage_mb"`
    NetworkUsageMB  int     `yaml:"network_usage_mb"`
    ExecutionTime   int     `yaml:"execution_time_seconds"`

    // IO characteristics
    IsIOHeavy       bool    `yaml:"is_io_heavy"`       // True for disk-intensive tools
    Weight          int64   `yaml:"weight"`            // Resource weight for semaphore (1-100)

    Priority        int     `yaml:"priority"`          // 1-10, higher = more important
}

type ToolUsage struct {
    ToolName        string
    PID             int
    StartTime       time.Time
    Resources       SystemResources
    Status          ExecutionStatus
}

type ResourceAllocation struct {
    // Weighted semaphore for automatic resource management
    TotalWeight     int64   `yaml:"total_weight"`      // Total resource units (e.g., 100)
    MaxIOHeavyTools int     `yaml:"max_io_heavy_tools"` // Max concurrent IO-intensive tools (1-2)

    // Legacy limits (for backward compatibility)
    MaxConcurrent   int     `yaml:"max_concurrent"`    // Fallback if semaphore fails
    MaxCPUPercent   float64 `yaml:"max_cpu_percent"`   // Default: 80%
    MaxMemPercent   float64 `yaml:"max_mem_percent"`   // Default: 85%
    MaxDiskPercent  float64 `yaml:"max_disk_percent"`  // Default: 90%
    ReserveCores    int     `yaml:"reserve_cores"`     // Keep 1 core free
}
```

**Weighted Semaphore аллокации:**
```go
func (rm *ResourceManager) allocateResources(ctx context.Context, tool string, repoSizeMB int64) error {
    rm.mu.Lock()
    profile := rm.toolProfiles[tool]
    rm.mu.Unlock()

    // Calculate dynamic resource requirements based on repo size
    estimatedMem := profile.BaseMemMB + int(float64(repoSizeMB) * profile.MemMultiplier)
    estimatedCPU := profile.BaseCPUMax + (float64(repoSizeMB) * profile.CPUMultiplier / 1000) // Per GB

    // Check if within absolute limits
    current := rm.monitor.getCurrentResources()
    if current.Memory.UsagePercent > rm.allocation.MaxMemPercent ||
       current.CPU.UsagePercent > rm.allocation.MaxCPUPercent {
        return fmt.Errorf("system resource limits exceeded")
    }

    // Acquire weighted semaphore (blocks if insufficient resources)
    weight := profile.Weight
    if err := rm.semaphore.Acquire(ctx, weight); err != nil {
        return fmt.Errorf("resource allocation failed: %w", err)
    }

    // Acquire IO semaphore if tool is IO-heavy
    if profile.IsIOHeavy {
        if err := rm.ioSemaphore.Acquire(ctx, 1); err != nil {
            rm.semaphore.Release(weight) // Release main semaphore
            return fmt.Errorf("IO resource allocation failed: %w", err)
        }
    }

    return nil
}

func (rm *ResourceManager) releaseResources(tool string) {
    rm.mu.Lock()
    profile := rm.toolProfiles[tool]
    rm.mu.Unlock()

    rm.semaphore.Release(profile.Weight)

    if profile.IsIOHeavy {
        rm.ioSemaphore.Release(1)
    }
}
```

### **3. ADAPTIVE EXECUTOR**
**Цель:** Умное планирование выполнения инструментов

```go
type AdaptiveExecutor struct {
    resourceManager *ResourceManager
    toolQueue       ToolQueue
    statusTracker   *StatusTracker
    executionMode   ExecutionMode
}

type ExecutionMode string
const (
    ParallelMode    ExecutionMode = "parallel"    // Run as many as possible
    SequentialMode  ExecutionMode = "sequential"  // Run one by one
    AdaptiveMode    ExecutionMode = "adaptive"    // Auto-switch based on resources
)

type ToolExecution struct {
    ToolName        string
    Config          *models.ToolConfig
    Status          ExecutionStatus
    Process         *os.Process         // For process group management
    PID             int
    PGID            int                 // Process Group ID for killing all children
    StartTime       time.Time
    EndTime         *time.Time
    ExitCode        int
    Error           error
    ResourceUsage   ToolUsage
    RetryCount      int
    MaxRetries      int
    CancelFunc      context.CancelFunc  // For graceful cancellation
}

type ExecutionStatus string
const (
    StatusPending     ExecutionStatus = "pending"      // Not started
    StatusQueued      ExecutionStatus = "queued"       // Waiting for resources
    StatusRunning     ExecutionStatus = "running"      // Currently executing
    StatusCompleted   ExecutionStatus = "completed"    // Finished successfully
    StatusFailed      ExecutionStatus = "failed"       // Failed with error
    StatusTimeout     ExecutionStatus = "timeout"      // Timed out
    StatusCancelled   ExecutionStatus = "cancelled"    // Cancelled by user/system
    StatusSkipped     ExecutionStatus = "skipped"      // Skipped due to conditions
)
```

**Алгоритм выполнения:**
```go
func (ae *AdaptiveExecutor) execute(ctx context.Context) error {
    // Determine execution mode
    mode := ae.determineExecutionMode()

    switch mode {
    case ParallelMode:
        return ae.executeParallel(ctx)
    case SequentialMode:
        return ae.executeSequential(ctx)
    case AdaptiveMode:
        return ae.executeAdaptive(ctx)
    }

    return nil
}

## 🔧 **КРИТИЧЕСКИЕ ИСПРАВЛЕНИЯ**

### **1. PROCESS GROUPS (Зомби-процессы)**
```go
func startToolWithProcessGroup(ctx context.Context, tool string, args []string) (*ToolExecution, error) {
    cmd := exec.CommandContext(ctx, tool, args...)

    // Create process group for reliable killing of all child processes
    cmd.SysProcAttr = &syscall.SysProcAttr{
        Setpgid: true,  // Create new process group
    }

    if err := cmd.Start(); err != nil {
        return nil, fmt.Errorf("failed to start tool %s: %w", tool, err)
    }

    // Get process group ID (negative of PID for killing)
    pgid, err := syscall.Getpgid(cmd.Process.Pid)
    if err != nil {
        pgid = cmd.Process.Pid // Fallback
    }

    execution := &ToolExecution{
        ToolName:   tool,
        Process:    cmd.Process,
        PID:        cmd.Process.Pid,
        PGID:       pgid,
        StartTime:  time.Now(),
        Status:     StatusRunning,
        CancelFunc: func() {
            // Kill entire process group
            syscall.Kill(-pgid, syscall.SIGTERM)
            time.Sleep(5 * time.Second)
            syscall.Kill(-pgid, syscall.SIGKILL)
        },
    }

    return execution, nil
}
```

### **2. WEIGHTED SEMAPHORE (Автоматическая очередь)**
```go
type ResourceManager struct {
    semaphore   *semaphore.Weighted  // 100 units total
    ioSemaphore *semaphore.Weighted  // Max 2 IO-heavy tools
}

func (rm *ResourceManager) allocateResources(ctx context.Context, tool string, repoSizeMB int64) error {
    profile := rm.toolProfiles[tool]

    // Calculate dynamic weight based on repo size
    weight := profile.Weight
    if repoSizeMB > 1000 { // >1GB repo
        weight = int64(float64(weight) * 1.5) // Increase weight for large repos
    }

    // Acquire semaphore (automatically blocks/queues if insufficient resources)
    if err := rm.semaphore.Acquire(ctx, weight); err != nil {
        return fmt.Errorf("resource allocation failed: %w", err)
    }

    // IO-heavy tools need additional semaphore
    if profile.IsIOHeavy {
        if err := rm.ioSemaphore.Acquire(ctx, 1); err != nil {
            rm.semaphore.Release(weight)
            return fmt.Errorf("IO resource allocation failed: %w", err)
        }
    }

    return nil
}
```

### **3. GRACEFUL SHUTDOWN**
```go
func setupGracefulShutdown(cancel context.CancelFunc, wg *sync.WaitGroup) {
    c := make(chan os.Signal, 1)
    signal.Notify(c, os.Interrupt, syscall.SIGTERM)

    go func() {
        <-c
        fmt.Println("\n🚨 Shutting down...")

        // 1. Cancel contexts (stop new starts)
        cancel()

        // 2. Kill all process groups
        killAllProcessGroups()

        // 3. Wait for cleanup
        wg.Wait()

        // 4. Clean temp files
        os.RemoveAll(tempDir)

        os.Exit(0)
    }()
}
```

func (ae *AdaptiveExecutor) determineExecutionMode() ExecutionMode {
    resources := ae.resourceManager.monitor.getCurrentResources()

    // Low resource system -> sequential
    if resources.Memory.Total < 8*1024*1024*1024 { // < 8GB RAM
        return SequentialMode
    }

    // High resource usage -> sequential
    if resources.CPU.UsagePercent > 80 || resources.Memory.UsagePercent > 85 {
        return SequentialMode
    }

    // Normal conditions -> parallel with limits
    return ParallelMode
}
```

### **4. STATUS TRACKER**
**Цель:** Отслеживание состояния выполнения всех инструментов

```go
type StatusTracker struct {
    executions  map[string]*ToolExecution
    history     []*ToolExecution
    listeners   []StatusListener
    mu          sync.RWMutex
}

type StatusListener interface {
    OnStatusChange(execution *ToolExecution)
    OnExecutionComplete(execution *ToolExecution)
    OnResourceAlert(alert ResourceAlert)
}

func (st *StatusTracker) UpdateStatus(toolName string, status ExecutionStatus, details map[string]interface{}) {
    st.mu.Lock()
    defer st.mu.Unlock()

    execution, exists := st.executions[toolName]
    if !exists {
        return
    }

    oldStatus := execution.Status
    execution.Status = status

    // Update additional fields based on status
    switch status {
    case StatusRunning:
        execution.StartTime = time.Now()
    case StatusCompleted, StatusFailed, StatusTimeout, StatusCancelled:
        endTime := time.Now()
        execution.EndTime = &endTime
    }

    // Update details
    if details != nil {
        if pid, ok := details["pid"].(int); ok {
            execution.PID = pid
        }
        if exitCode, ok := details["exit_code"].(int); ok {
            execution.ExitCode = exitCode
        }
        if err, ok := details["error"].(error); ok {
            execution.Error = err
        }
    }

    // Notify listeners
    for _, listener := range st.listeners {
        listener.OnStatusChange(execution)

        if status.IsTerminal() {
            listener.OnExecutionComplete(execution)
        }
    }
}
```

### **5. RESULTS AGGREGATOR WITH STATUS FLAGS**
**Цель:** Обогащение JSON результатов флагами статуса

```go
type OrchestratorResult struct {
    ScanID          string             `json:"scan_id"`
    Timestamp       time.Time          `json:"timestamp"`
    Target          string             `json:"target"`
    ExecutionMode   ExecutionMode      `json:"execution_mode"`
    Duration        time.Duration      `json:"duration_seconds"`

    // Resource usage summary
    Resources       struct {
        PeakCPU       float64 `json:"peak_cpu_percent"`
        PeakMemory    uint64  `json:"peak_memory_mb"`
        TotalDiskUsed uint64  `json:"total_disk_mb"`
    } `json:"resources"`

    // Tool executions with status
    Tools           []ToolResult       `json:"tools"`

    // Overall status
    Status          ScanStatus         `json:"status"`
    Error           string             `json:"error,omitempty"`
}

type ToolResult struct {
    Name            string            `json:"name"`
    Version         string            `json:"version"`
    Status          ExecutionStatus   `json:"status"`
    Duration        time.Duration     `json:"duration_seconds"`
    ExitCode        int               `json:"exit_code"`

    // Resource usage
    Resources       ToolUsage         `json:"resources"`

    // Findings
    Findings        []models.Finding  `json:"findings"`
    FindingCount    int               `json:"finding_count"`

    // Error details
    Error           string            `json:"error,omitempty"`
    Stdout          string            `json:"stdout,omitempty"`
    Stderr          string            `json:"stderr,omitempty"`

    // Metadata
    StartTime       time.Time         `json:"start_time"`
    EndTime         *time.Time        `json:"end_time,omitempty"`
    RetryCount      int               `json:"retry_count"`
}

type ScanStatus string
const (
    ScanPending     ScanStatus = "pending"
    ScanRunning     ScanStatus = "running"
    ScanCompleted   ScanStatus = "completed"
    ScanFailed      ScanStatus = "failed"
    ScanPartial     ScanStatus = "partial"  // Some tools failed
)
```

**Пример JSON вывода:**
```json
{
  "scan_id": "scan_20241201_143052",
  "timestamp": "2024-12-01T14:30:52Z",
  "target": "/path/to/project",
  "execution_mode": "adaptive",
  "duration_seconds": 245,
  "resources": {
    "peak_cpu_percent": 85.2,
    "peak_memory_mb": 4096,
    "total_disk_mb": 2048
  },
  "tools": [
    {
      "name": "semgrep",
      "version": "1.150.0",
      "status": "completed",
      "duration_seconds": 45,
      "exit_code": 0,
      "resources": {
        "cpu_percent": 75.3,
        "memory_mb": 1024
      },
      "findings": [...],
      "finding_count": 23,
      "start_time": "2024-12-01T14:30:52Z",
      "end_time": "2024-12-01T14:31:37Z"
    },
    {
      "name": "trivy",
      "version": "0.69.0",
      "status": "running",
      "duration_seconds": 120,
      "exit_code": null,
      "resources": {
        "cpu_percent": 45.1,
        "memory_mb": 512
      },
      "findings": null,
      "finding_count": 0,
      "start_time": "2024-12-01T14:32:00Z"
    },
    {
      "name": "gosec",
      "version": "2.22.1",
      "status": "failed",
      "duration_seconds": 5,
      "exit_code": 1,
      "error": "out of memory",
      "start_time": "2024-12-01T14:31:00Z",
      "end_time": "2024-12-01T14:31:05Z"
    }
  ],
  "status": "running"
}
```

## 🔧 **КОНФИГУРАЦИЯ**

### **Resource Manager Config**
```yaml
resource_manager:
  monitoring:
    interval_seconds: 5
    history_size: 100

  thresholds:
    cpu_warning: 70.0
    cpu_critical: 90.0
    mem_warning: 80.0
    mem_critical: 95.0
    disk_warning: 85.0
    disk_critical: 95.0

  allocation:
    # Weighted semaphore configuration
    total_weight: 100              # Total resource units
    max_io_heavy_tools: 2          # Max concurrent IO-intensive tools

    # Legacy limits (fallback)
    max_concurrent: 3
    max_cpu_percent: 80.0
    max_mem_percent: 85.0
    max_disk_percent: 90.0
    reserve_cores: 1

  tool_profiles:
    semgrep:
      # Dynamic scaling based on repo size
      base_mem_mb: 512
      mem_multiplier: 1.0         # +1MB RAM per MB of repo
      base_cpu_max: 30.0
      cpu_multiplier: 0.02        # +2% CPU per GB of repo

      # Static limits
      disk_usage_mb: 500
      execution_time_seconds: 300

      # IO characteristics
      is_io_heavy: true           # High disk I/O
      weight: 35                  # Resource cost (out of 100)

      priority: 8

    trivy:
      base_mem_mb: 256
      mem_multiplier: 0.5
      base_cpu_max: 20.0
      cpu_multiplier: 0.01
      disk_usage_mb: 1000
      execution_time_seconds: 600
      is_io_heavy: true           # Downloads DB, scans filesystem
      weight: 40
      priority: 7

    gosec:
      base_mem_mb: 128
      mem_multiplier: 0.2
      base_cpu_max: 15.0
      cpu_multiplier: 0.005
      disk_usage_mb: 100
      execution_time_seconds: 120
      is_io_heavy: false
      weight: 10
      priority: 6

    trivy:
      memory_peak_mb: 1024
      memory_avg_mb: 512
      cpu_max_percent: 50.0
      disk_usage_mb: 1000
      execution_time_seconds: 600
      priority: 7

    gosec:
      memory_peak_mb: 512
      memory_avg_mb: 256
      cpu_max_percent: 30.0
      disk_usage_mb: 100
      execution_time_seconds: 120
      priority: 6
```

### **Execution Config**
```yaml
execution:
  mode: "adaptive"  # parallel | sequential | adaptive
  timeout_seconds: 1800
  retry_attempts: 2
  retry_delay_seconds: 30

  priorities:
    - semgrep
    - trivy
    - checkov
    - owasp-dep-check
    - bandit
    - njsscan
    - hadolint
    - gitleaks
    - osv-scanner
    - govulncheck
    - safety

  failure_policy: "continue"  # continue | stop | ask
```

## 📊 **METRICS & DASHBOARD**

### **Real-time Dashboard**
```
System Resources: CPU: 65% | Memory: 4.2GB/8GB | Disk: 45GB/100GB

Tool Status:
✅ semgrep     (45s) - 23 findings
🔄 trivy       (120s) - running
❌ gosec       (5s) - OOM failed
⏳ bandit      (queued) - waiting
⏸️  checkov    (paused) - resource limit

Queue: bandit, njsscan, hadolint, gitleaks
Completed: 3/12 | Failed: 1/12 | Running: 1/12
```

### **Performance Metrics**
```go
type ExecutionMetrics struct {
    TotalTools          int     `json:"total_tools"`
    CompletedTools      int     `json:"completed_tools"`
    FailedTools         int     `json:"failed_tools"`
    AvgExecutionTime    float64 `json:"avg_execution_time_seconds"`
    ResourceEfficiency  float64 `json:"resource_efficiency_percent"`
    ParallelizationRate float64 `json:"parallelization_rate_percent"`
}
```

## 🚀 **IMPLEMENTATION ROADMAP**

### **Phase 1: Core Infrastructure** (1 week)
- [ ] Weighted semaphore implementation (golang.org/x/sync/semaphore)
- [ ] Process groups for reliable process management (Setpgid)
- [ ] Graceful shutdown with signal handling
- [ ] Basic resource monitoring

### **Phase 2: Dynamic Profiles** (2 weeks)
- [ ] Repo size detection (du -sh equivalent)
- [ ] Dynamic resource calculation based on repo size
- [ ] IO-heavy tool throttling (MaxIOHeavyTools)
- [ ] Tool priority queues

### **Phase 3: Adaptive Execution** (2 weeks)
- [ ] Resource-aware scheduling with weighted semaphore
- [ ] Automatic mode switching (parallel ↔ sequential)
- [ ] Process group cleanup and zombie prevention
- [ ] Resource usage tracking per tool

### **Phase 4: Production Hardening** (1 week)
- [x] Container resource detection (cgroups limits)
- [x] Goroutine panic recovery with semaphore release
- [x] Temp file garbage collection on startup
- [x] Manual memory limit override flags
- [ ] Performance monitoring

## 🎯 **SUCCESS CRITERIA**

- **No Zombie Processes:** All child processes killed reliably with process groups
- **Resource Efficiency:** <85% system resource usage (weighted semaphore)
- **No Disk I/O Contention:** Max 2 IO-heavy tools concurrent (Trivy, Semgrep, etc.)
- **Dynamic Scaling:** Resource allocation scales with repository size
- **Graceful Shutdown:** Clean exit with temp file cleanup on Ctrl+C
- **No Race Conditions:** Weighted semaphore prevents resource conflicts
- **Execution Time:** 50% faster than sequential with proper parallelization
- **Container Safe:** Reads cgroups limits, prevents OOM in Docker/K8s
- **Panic Safe:** Goroutines recover, release semaphores, don't crash orchestrator
- **Disk Safe:** Garbage collection prevents temp file accumulation

## 🔍 **FAILURE MODES & RECOVERY**

### **Resource Exhaustion**
1. **Detection:** Monitor alerts trigger
2. **Response:** Pause low-priority tools
3. **Recovery:** Resume when resources free

### **Tool Crashes**
1. **Detection:** Process exit with non-zero code
2. **Response:** Log error, mark as failed
3. **Recovery:** Retry if retry policy allows

### **System Overload**
1. **Detection:** Critical thresholds exceeded
2. **Response:** Emergency stop all tools
3. **Recovery:** Manual restart with sequential mode

## 🚨 **PRODUCTION HARDENING (CRITICAL FOR CI/CD)**

### **1. CONTAINER RESOURCE DETECTION (CGROUPS FIX)**
```go
func detectContainerEnvironment() bool {
    // Check for container indicators
    if _, err := os.Stat("/.dockerenv"); err == nil {
        return true
    }
    if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
        return strings.Contains(string(data), "docker") ||
               strings.Contains(string(data), "containerd")
    }
    return false
}

func readCgroupMemoryLimit() uint64 {
    // Read from /sys/fs/cgroup/memory/memory.limit_in_bytes
    if data, err := os.ReadFile("/sys/fs/cgroup/memory/memory.limit_in_bytes"); err == nil {
        if limit, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64); err == nil {
            // Check if limit is reasonable (not unlimited)
            if limit < 1024*1024*1024*1024 { // < 1TB
                return limit
            }
        }
    }
    return 0
}

func (rm *ResourceMonitor) collectResources() SystemResources {
    resources := SystemResources{Timestamp: time.Now()}

    // Detect if running in container
    resources.Memory.IsContainer = detectContainerEnvironment()

    // Get memory info
    if resources.Memory.IsContainer {
        // Read container limits from cgroups
        if cgroupLimit := readCgroupMemoryLimit(); cgroupLimit > 0 {
            resources.Memory.CgroupLimit = cgroupLimit
            resources.Memory.Total = cgroupLimit // Use container limit, not host total
        }
    }

    // Fallback to system info if not in container
    if resources.Memory.Total == 0 {
        resources.Memory.Total = getSystemMemoryTotal()
    }

    // ... rest of collection logic
    return resources
}
```

**YAML Override:**
```yaml
resource_manager:
  manual_limits:
    max_memory_gb: 2        # Override auto-detection for containers
    max_cpu_cores: 1        # For restricted environments
```

### **2. GOROUTINE PANIC RECOVERY**
```go
func (ae *AdaptiveExecutor) startToolGoroutine(execution *ToolExecution) {
    go func() {
        defer func() {
            if r := recover(); r != nil {
                // LOG PANIC but don't crash orchestrator
                log.Printf("PANIC in tool %s: %v", execution.ToolName, r)

                // Update status to failed
                execution.Status = StatusFailed
                execution.Error = fmt.Errorf("panic: %v", r)

                // CRITICAL: Release semaphore to prevent deadlock
                ae.resourceManager.releaseResources(execution.ToolName)

                // Try to kill process group if it started
                if execution.Process != nil {
                    killToolExecution(execution)
                }
            }
        }()

        // Tool execution logic here
        ae.runToolExecution(execution)
    }()
}
```

### **3. TEMP FILE GARBAGE COLLECTION**
```go
func cleanupOrphanedTempDirs() error {
    tempBase := os.TempDir()
    pattern := filepath.Join(tempBase, "afss-scan-*")

    matches, err := filepath.Glob(pattern)
    if err != nil {
        return err
    }

    for _, dir := range matches {
        info, err := os.Stat(dir)
        if err != nil {
            continue
        }

        // Remove dirs older than 24 hours
        if time.Since(info.ModTime()) > 24*time.Hour {
            if err := os.RemoveAll(dir); err != nil {
                log.Printf("Failed to cleanup temp dir %s: %v", dir, err)
            } else {
                log.Printf("Cleaned up orphaned temp dir: %s", dir)
            }
        }
    }

    return nil
}

func initOrchestrator() error {
    // CRITICAL: Clean up before starting
    if err := cleanupOrphanedTempDirs(); err != nil {
        return fmt.Errorf("failed to cleanup temp dirs: %w", err)
    }

    // ... rest of initialization
    return nil
}
```

### **4. UPDATED SUCCESS CRITERIA**
- ✅ **Container Aware:** Reads cgroups limits, not host total memory
- ✅ **Panic Safe:** Goroutines recover from panics, release semaphores
- ✅ **Temp File Safe:** Garbage collection on startup prevents disk overflow
- ✅ **OOM Protected:** Manual limits override for restricted environments

## 🚀 **ИТОГОВЫЙ ВЕРДИКТ**

✅ **Внедряй эти решения:**

1. **Weighted Semaphore** - автоматическая очередь, 10x проще чем ручной подсчет
2. **Process Groups** - надежное убийство всех процессов (родитель + дети)
3. **IO Throttling** - лимит на дисковые операции (MaxIOHeavyTools: 2)
4. **Dynamic Scaling** - ресурсы масштабируются с размером репозитория
5. **Graceful Shutdown** - чистый выход с уборкой мусора
6. **Container Detection** - читает cgroups лимиты, предотвращает OOM в Docker
7. **Panic Recovery** - горутины recover от panic, освобождают семафоры
8. **Temp File GC** - уборка сиротских директорий при старте

❌ **Не изобретай велосипеды:**
- Не пиши свой semaphore
- Не пытайся manually считать ресурсы
- Не игнорируй IO contention
- Не игнорируй container environments
- Не забывай про panic recovery
- Не оставляй temp файлы без GC

**Результат:** Оркестратор, который не убивает сервер и правильно управляет 12 инструментами.

---

**Этот Resource Manager превратит хаотичный запуск в контролируемое, эффективное сканирование без риска для системы.**
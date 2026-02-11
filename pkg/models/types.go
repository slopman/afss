package models

import (
	"time"
)

// ResourceSnapshot represents system resource usage at a point in time
type ResourceSnapshot struct {
	Timestamp    time.Time `json:"timestamp"`
	MemoryUsedMB int       `json:"memory_used_mb"`
	MemoryTotalMB int      `json:"memory_total_mb"`
	MemoryPercent float64   `json:"memory_percent"`
	CPUUsedPercent float64  `json:"cpu_used_percent"`
	DiskUsedMB   int       `json:"disk_used_mb"`
	DiskFreeMB   int       `json:"disk_free_mb"`
}

// ToolResourceProfile represents resource consumption profile for a tool
type ToolResourceProfile struct {
	ToolName          string        `json:"tool_name"`
	MemoryPeakMB      int           `json:"memory_peak_mb"`
	MemoryAvgMB       int           `json:"memory_avg_mb"`
	CPUAvgPercent     float64       `json:"cpu_avg_percent"`
	ExpectedDuration  time.Duration `json:"expected_duration"`
	TempSpaceMB       int           `json:"temp_space_mb"`
	SuccessRate       float64       `json:"success_rate"`
	SampleCount       int           `json:"sample_count"`
}

// ToolExecution represents a running tool instance
type ToolExecution struct {
	ToolName    string        `json:"tool_name"`
	PID         int           `json:"pid"`
	StartTime   time.Time     `json:"start_time"`
	ResourceLimits ResourceLimits `json:"resource_limits"`
	Status      ExecutionStatus `json:"status"`
}

// ResourceLimits defines resource constraints for tool execution
type ResourceLimits struct {
	MaxMemoryMB   int     `json:"max_memory_mb"`
	MaxCPUPercent float64 `json:"max_cpu_percent"`
	Timeout       time.Duration `json:"timeout"`
}

// ExecutionStatus represents the current status of tool execution
type ExecutionStatus string

const (
	StatusPending   ExecutionStatus = "pending"
	StatusRunning   ExecutionStatus = "running"
	StatusCompleted ExecutionStatus = "completed"
	StatusFailed    ExecutionStatus = "failed"
	StatusTimeout   ExecutionStatus = "timeout"
	StatusKilled    ExecutionStatus = "killed"
)

// ToolConfig represents configuration for a security tool
type ToolConfig struct {
	Tool        string                 `yaml:"tool"`
	Enabled     bool                   `yaml:"enabled"`
	Description string                 `yaml:"description,omitempty"`

	ResourceProfile ToolResourceProfile `yaml:"resource_profile"`

	CLI map[string]interface{} `yaml:"cli"`

	Conditions []Condition `yaml:"conditions,omitempty"`

	Metadata map[string]interface{} `yaml:"metadata,omitempty"`
}

// Condition represents a precondition for running a tool
type Condition struct {
	Type    string `yaml:"type"`    // file_exists, not_file_exists, is_git_repo, etc.
	Pattern string `yaml:"pattern"`
}

// OrchestratorConfig represents the main orchestrator configuration
type OrchestratorConfig struct {
	Version string `yaml:"version"`

	Global struct {
		TimeoutSeconds      int    `yaml:"timeout_seconds"`
		TempDir            string `yaml:"temp_dir"`
		LogLevel           string `yaml:"log_level"`
		ConfigDir          string `yaml:"config_dir"`
	} `yaml:"global"`

	Resources struct {
		MaxParallelScans       int     `yaml:"max_parallel_scans"`
		MemoryLimitPercent     float64 `yaml:"memory_limit_percent"`
		CPULimitPercent        float64 `yaml:"cpu_limit_percent"`
		AdaptiveThrottling     bool    `yaml:"adaptive_throttling"`
		SnapshotIntervalSeconds int    `yaml:"snapshot_interval_seconds"`
		ResourceCheckIntervalSeconds int `yaml:"resource_check_interval_seconds"`
	} `yaml:"resources"`

	Execution struct {
		Mode              string         `yaml:"mode"` // resource_aware, parallel, sequential
		ToolPriority      map[string]int `yaml:"tool_priority"`
		DefaultResourceLimits ResourceLimits `yaml:"default_resource_limits"`
	} `yaml:"execution"`

	Output struct {
		Format         string `yaml:"format"` // json, sarif, html
		CombineResults bool   `yaml:"combine_results"`
		SaveIntermediate bool `yaml:"save_intermediate"`
		ResultsDir     string `yaml:"results_dir"`
	} `yaml:"output"`
}

// ScanRequest represents a scan execution request
type ScanRequest struct {
	ID       string            `json:"id"`
	RepoPath string            `json:"repo_path"`
	Config   OrchestratorConfig `json:"config"`
	Tools    []string          `json:"tools,omitempty"` // specific tools to run, empty = all enabled
}

// ScanResult represents the result of a complete scan
type ScanResult struct {
	ID           string                `json:"id"`
	StartTime    time.Time             `json:"start_time"`
	EndTime      time.Time             `json:"end_time"`
	Duration     time.Duration         `json:"duration"`
	Status       string                `json:"status"`
	ToolResults  []ToolResult          `json:"tool_results"`
	ResourceUsage []ResourceSnapshot   `json:"resource_usage"`
	Summary      ScanSummary           `json:"summary"`
}

// ToolResult represents the result of a single tool execution
type ToolResult struct {
	ToolName       string                 `json:"tool_name"`
	Status         ExecutionStatus        `json:"status"`
	StartTime      time.Time              `json:"start_time"`
	EndTime        time.Time              `json:"end_time"`
	Duration       time.Duration          `json:"duration"`
	ResourceUsage  []ResourceSnapshot     `json:"resource_usage"`
	Output         string                 `json:"output,omitempty"`
	Error          string                 `json:"error,omitempty"`
	Findings       []Finding              `json:"findings,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// Finding represents a single security finding
type Finding struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"` // Critical, High, Medium, Low, Info
	Confidence  string    `json:"confidence"` // High, Medium, Low
	File        string    `json:"file"`
	Line         int       `json:"line"`
	Column      int       `json:"column,omitempty"`
	CodeSnippet string    `json:"code_snippet,omitempty"`
	Category    string    `json:"category"` // git, code, secrets, deps, blockchain
	RuleID      string    `json:"rule_id"`
	Tags        []string  `json:"tags,omitempty"`
	CWE         string    `json:"cwe,omitempty"`
	References  []string  `json:"references,omitempty"`
	Tool        string    `json:"tool"` // which tool found this
}

// ScanSummary provides a high-level overview of scan results
type ScanSummary struct {
	TotalFindings    int            `json:"total_findings"`
	SeverityBreakdown map[string]int `json:"severity_breakdown"`
	CategoryBreakdown map[string]int `json:"category_breakdown"`
	ToolBreakdown    map[string]int `json:"tool_breakdown"`
	ScanCoverage     float64        `json:"scan_coverage"`
	RiskScore        float64        `json:"risk_score"`
}
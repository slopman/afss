package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
	"github.com/sirupsen/logrus"

	"github.com/security-scanner/afss-orchestrator/pkg/models"
)

// Manager handles loading and validation of tool configurations
type Manager struct {
	configDir string
	logger    *logrus.Logger
	validator *Validator
}

// NewManager creates a new configuration manager
func NewManager(configDir string, logger *logrus.Logger) *Manager {
	return &Manager{
		configDir: configDir,
		logger:    logger,
		validator: NewValidator(logger),
	}
}

// LoadOrchestratorConfig loads the main orchestrator configuration
func (m *Manager) LoadOrchestratorConfig(configPath string) (*models.OrchestratorConfig, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read orchestrator config: %w", err)
	}

	// First parse into a map to extract the orchestrator block
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse orchestrator config: %w", err)
	}

	// Extract the orchestrator block
	orchData, ok := raw["orchestrator"]
	if !ok {
		return nil, fmt.Errorf("orchestrator config must have 'orchestrator' root key")
	}

	// Convert back to YAML bytes for structured parsing
	orchBytes, err := yaml.Marshal(orchData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal orchestrator data: %w", err)
	}

	var config models.OrchestratorConfig
	if err := yaml.Unmarshal(orchBytes, &config); err != nil {
		return nil, fmt.Errorf("failed to parse orchestrator config structure: %w", err)
	}

	if err := m.validator.ValidateOrchestratorConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid orchestrator config: %w", err)
	}

	m.logger.Info("Loaded orchestrator config", "path", configPath, "version", config.Version)
	return &config, nil
}

// LoadToolConfig loads configuration for a specific tool
func (m *Manager) LoadToolConfig(toolName string) (*models.ToolConfig, error) {
	configPath := filepath.Join(m.configDir, "tools", toolName+".yaml")

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read tool config for %s: %w", toolName, err)
	}

	var config models.ToolConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse tool config for %s: %w", toolName, err)
	}

	if err := m.validator.ValidateToolConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid tool config for %s: %w", toolName, err)
	}

	m.logger.Debug("Loaded tool config", "tool", toolName, "path", configPath)
	return &config, nil
}

// LoadAllToolConfigs loads configurations for all enabled tools
func (m *Manager) LoadAllToolConfigs() (map[string]*models.ToolConfig, error) {
	toolConfigs := make(map[string]*models.ToolConfig)

	toolsDir := filepath.Join(m.configDir, "tools")
	entries, err := os.ReadDir(toolsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read tools config directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}

		toolName := entry.Name()[:len(entry.Name())-5] // remove .yaml extension

		config, err := m.LoadToolConfig(toolName)
		if err != nil {
			m.logger.Warn("Failed to load tool config", "tool", toolName, "error", err)
			continue
		}

		if config.Enabled {
			toolConfigs[toolName] = config
		}
	}

	m.logger.Info("Loaded tool configs", "count", len(toolConfigs))
	return toolConfigs, nil
}

// SaveToolConfig saves a tool configuration to disk
func (m *Manager) SaveToolConfig(toolName string, config *models.ToolConfig) error {
	configPath := filepath.Join(m.configDir, "tools", toolName+".yaml")

	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal tool config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write tool config: %w", err)
	}

	m.logger.Info("Saved tool config", "tool", toolName, "path", configPath)
	return nil
}

// UpdateToolConfigParameter updates a specific parameter in tool config
func (m *Manager) UpdateToolConfigParameter(toolName, paramPath string, value interface{}) error {
	config, err := m.LoadToolConfig(toolName)
	if err != nil {
		return err
	}

	// Simple parameter update (can be extended for nested parameters)
	switch paramPath {
	case "enabled":
		if enabled, ok := value.(bool); ok {
			config.Enabled = enabled
		}
	case "resource_profile.memory_mb":
		if memory, ok := value.(int); ok {
			config.ResourceProfile.MemoryPeakMB = memory
		}
	// Add more parameter paths as needed
	default:
		return fmt.Errorf("unknown parameter path: %s", paramPath)
	}

	return m.SaveToolConfig(toolName, config)
}

// CreateDefaultConfigs creates default configuration files
func (m *Manager) CreateDefaultConfigs() error {
	// Create tools directory
	toolsDir := filepath.Join(m.configDir, "tools")
	if err := os.MkdirAll(toolsDir, 0755); err != nil {
		return fmt.Errorf("failed to create tools config directory: %w", err)
	}

	// Create orchestrator config
	orchConfig := m.createDefaultOrchestratorConfig()
	orchPath := filepath.Join(m.configDir, "orchestrator.yaml")
	if err := m.saveConfig(orchPath, orchConfig); err != nil {
		return fmt.Errorf("failed to create orchestrator config: %w", err)
	}

	// Create default tool configs
	defaultTools := map[string]*models.ToolConfig{
		"gosec":            m.createGosecConfig(),
		"semgrep":          m.createSemgrepConfig(),
		"trufflehog":       m.createTruffleHogConfig(),
		"owasp-dep-check":  m.createOWASPDepCheckConfig(),
		"govulncheck":      m.createGovulncheckConfig(),
	}

	for toolName, config := range defaultTools {
		configPath := filepath.Join(toolsDir, toolName+".yaml")
		if err := m.saveConfig(configPath, config); err != nil {
			m.logger.Warn("Failed to create default config", "tool", toolName, "error", err)
		}
	}

	m.logger.Info("Created default configuration files")
	return nil
}

// Helper methods for creating default configs
func (m *Manager) createDefaultOrchestratorConfig() *models.OrchestratorConfig {
	config := &models.OrchestratorConfig{}
	config.Version = "1.0"

	config.Global.TimeoutSeconds = 1800
	config.Global.TempDir = "/tmp/afss-orchestrator"
	config.Global.LogLevel = "info"
	config.Global.ConfigDir = m.configDir

	config.Resources.MaxParallelScans = 2
	config.Resources.MemoryLimitPercent = 80.0
	config.Resources.CPULimitPercent = 70.0
	config.Resources.AdaptiveThrottling = true
	config.Resources.SnapshotIntervalSeconds = 5
	config.Resources.ResourceCheckIntervalSeconds = 10

	config.Execution.Mode = "resource_aware"
	config.Execution.ToolPriority = map[string]int{
		"gosec":     1,
		"semgrep":   2,
		"trufflehog": 3,
	}
	config.Execution.DefaultResourceLimits = models.ResourceLimits{
		MaxMemoryMB:   512,
		MaxCPUPercent: 50.0,
		Timeout:       300 * time.Second,
	}

	config.Output.Format = "json"
	config.Output.CombineResults = true
	config.Output.SaveIntermediate = true
	config.Output.ResultsDir = "./results"

	return config
}

func (m *Manager) createGosecConfig() *models.ToolConfig {
	config := &models.ToolConfig{
		Tool:        "gosec",
		Enabled:     true,
		Description: "Go static security analysis",

		ResourceProfile: models.ToolResourceProfile{
			ToolName:         "gosec",
			MemoryPeakMB:     256,
			CPUAvgPercent:    50.0,
			ExpectedDuration: 120 * time.Second,
			TempSpaceMB:      100,
		},

		CLI: map[string]interface{}{
			"severity":        "medium",
			"confidence":      "medium",
			"no_fail":         true,
			"quiet":          true,
			"exclude_generated": true,
			"concurrency":    2,
			"output_format":  "json",
		},

		Conditions: []models.Condition{
			{Type: "file_exists", Pattern: "*.go"},
		},
	}

	return config
}

func (m *Manager) createSemgrepConfig() *models.ToolConfig {
	config := &models.ToolConfig{
		Tool:        "semgrep",
		Enabled:     true,
		Description: "Multi-language semantic code analysis",

		ResourceProfile: models.ToolResourceProfile{
			ToolName:         "semgrep",
			MemoryPeakMB:     512,
			CPUAvgPercent:    60.0,
			ExpectedDuration: 300 * time.Second,
			TempSpaceMB:      200,
		},

		CLI: map[string]interface{}{
			"config": "auto",
			"json":   true,
			"quiet":  true,
			"error":  false,
			"max_target_bytes": 1000000,
			"jobs":   2,
		},
	}

	return config
}

func (m *Manager) createTruffleHogConfig() *models.ToolConfig {
	config := &models.ToolConfig{
		Tool:        "trufflehog",
		Enabled:     true,
		Description: "Git secrets scanning",

		ResourceProfile: models.ToolResourceProfile{
			ToolName:         "trufflehog",
			MemoryPeakMB:     128,
			CPUAvgPercent:    30.0,
			ExpectedDuration: 180 * time.Second,
			TempSpaceMB:      50,
		},

		CLI: map[string]interface{}{
			"json":           true,
			"no_verification": true,
			"concurrency":    2,
			"archive_max_size": "10MB",
			"detector_timeout": "30s",
		},

		Conditions: []models.Condition{
			{Type: "is_git_repo"},
		},
	}

	return config
}

func (m *Manager) createOWASPDepCheckConfig() *models.ToolConfig {
	config := &models.ToolConfig{
		Tool:        "owasp-dep-check",
		Enabled:     true,
		Description: "OWASP Dependency Check - Multi-language dependency vulnerability scanner",

		ResourceProfile: models.ToolResourceProfile{
			ToolName:         "owasp-dep-check",
			MemoryPeakMB:     1024,
			CPUAvgPercent:    40.0,
			ExpectedDuration: 600 * time.Second,
			TempSpaceMB:      500,
		},

		CLI: map[string]interface{}{
			"scan":             ".",
			"format":           "JSON",
			"prettyPrint":      true,
			"disableAutoUpdate": true,
			"failOnCVSS":       0,
		},

		Conditions: []models.Condition{
			{Type: "file_exists", Pattern: "pom.xml"},
			{Type: "file_exists", Pattern: "build.gradle"},
			{Type: "file_exists", Pattern: "package.json"},
			{Type: "file_exists", Pattern: "requirements.txt"},
			{Type: "file_exists", Pattern: "*.csproj"},
		},
	}

	return config
}

func (m *Manager) createGovulncheckConfig() *models.ToolConfig {
	config := &models.ToolConfig{
		Tool:        "govulncheck",
		Enabled:     true,
		Description: "Go vulnerability database checker",

		ResourceProfile: models.ToolResourceProfile{
			ToolName:         "govulncheck",
			MemoryPeakMB:     256,
			CPUAvgPercent:    30.0,
			ExpectedDuration: 180 * time.Second,
			TempSpaceMB:      50,
		},

		CLI: map[string]interface{}{
			"format": "json",
			"scan":   "package",
			"show":   "verbose",
		},

		Conditions: []models.Condition{
			{Type: "file_exists", Pattern: "go.mod"},
		},
	}

	return config
}

// saveConfig is a helper to save config to file
func (m *Manager) saveConfig(path string, config interface{}) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
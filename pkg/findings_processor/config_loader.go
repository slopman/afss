package findings_processor

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ConfigLoader handles loading configuration from YAML files
type ConfigLoader struct{}

// NewConfigLoader creates a new configuration loader
func NewConfigLoader() *ConfigLoader {
	return &ConfigLoader{}
}

// LoadConfigFromFile loads processor configuration from a YAML file
func (cl *ConfigLoader) LoadConfigFromFile(configPath string) (*ProcessorConfig, error) {
	// Check if file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("config file does not exist: %s", configPath)
	}

	// Read file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse YAML
	var fullConfig FindingsProcessorConfig
	if err := yaml.Unmarshal(data, &fullConfig); err != nil {
		return nil, fmt.Errorf("failed to parse config YAML: %w", err)
	}

	config := fullConfig.FindingsProcessor

	// Validate configuration
	if err := cl.validateConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &config, nil
}

// LoadDefaultConfig loads default configuration merged with YAML if available
func (cl *ConfigLoader) LoadDefaultConfig() (*ProcessorConfig, error) {
	// Start with default config
	config := DefaultConfig()

	// Try to load from standard locations
	configPaths := []string{
		"./configs/findings_processor_filtering.yaml",
		"../configs/findings_processor_filtering.yaml",
		filepath.Join(os.Getenv("HOME"), ".afss", "configs", "findings_processor_filtering.yaml"),
	}

	for _, path := range configPaths {
		if yamlConfig, err := cl.LoadConfigFromFile(path); err == nil {
			// Merge YAML config with defaults
			config = cl.mergeConfigs(config, *yamlConfig)
			break
		}
	}

	return &config, nil
}

// mergeConfigs merges YAML configuration with default configuration
func (cl *ConfigLoader) mergeConfigs(defaultConfig, yamlConfig ProcessorConfig) ProcessorConfig {
	// Use YAML config where available, fallback to defaults
	result := defaultConfig

	// Merge filtering settings
	if len(yamlConfig.Filtering.StatisticalFilters) > 0 {
		result.Filtering.StatisticalFilters = yamlConfig.Filtering.StatisticalFilters
	}
	if yamlConfig.Filtering.MinSeverity != "" {
		result.Filtering.MinSeverity = yamlConfig.Filtering.MinSeverity
	}
	if yamlConfig.Filtering.MinConfidence != "" {
		result.Filtering.MinConfidence = yamlConfig.Filtering.MinConfidence
	}
	if len(yamlConfig.Filtering.ExcludePaths) > 0 {
		result.Filtering.ExcludePaths = yamlConfig.Filtering.ExcludePaths
	}
	if len(yamlConfig.Filtering.IncludePaths) > 0 {
		result.Filtering.IncludePaths = yamlConfig.Filtering.IncludePaths
	}

	// Merge output settings
	if len(yamlConfig.Output.Formats) > 0 {
		result.Output.Formats = yamlConfig.Output.Formats
	}
	if yamlConfig.Output.MaxFindings > 0 {
		result.Output.MaxFindings = yamlConfig.Output.MaxFindings
	}
	if yamlConfig.Output.GroupBy != "" {
		result.Output.GroupBy = yamlConfig.Output.GroupBy
	}

	// Merge deduplication settings from YAML
	if yamlConfig.DeduplicationConfig.Enabled {
		result.EnableDeduplication = yamlConfig.DeduplicationConfig.Enabled
	}
	if yamlConfig.DeduplicationConfig.SimilarityThreshold > 0 {
		// Could be used for future similarity-based deduplication
	}
	if yamlConfig.DeduplicationConfig.AggressiveNormalization {
		result.Deduplication.EnableAggressiveHashing = yamlConfig.DeduplicationConfig.AggressiveNormalization
	}

	return result
}

// validateConfig validates the loaded configuration
func (cl *ConfigLoader) validateConfig(config *ProcessorConfig) error {
	// Validate severity levels (allow empty = use defaults)
	validSeverities := map[SeverityLevel]bool{
		Critical: true, High: true, Medium: true, Low: true, Info: true,
	}
	if config.Filtering.MinSeverity != "" && !validSeverities[config.Filtering.MinSeverity] {
		return fmt.Errorf("invalid min_severity: %s", config.Filtering.MinSeverity)
	}

	// Validate confidence levels (allow empty = use defaults)
	validConfidences := map[ConfidenceLevel]bool{
		Certain: true, Likely: true, Possible: true,
	}
	if config.Filtering.MinConfidence != "" && !validConfidences[config.Filtering.MinConfidence] {
		return fmt.Errorf("invalid min_confidence: %s", config.Filtering.MinConfidence)
	}

	// Validate statistical filters
	for i, rule := range config.Filtering.StatisticalFilters {
		if rule.Pattern == "" {
			return fmt.Errorf("statistical filter rule %d: pattern cannot be empty", i)
		}
		if rule.FilePattern == "" {
			return fmt.Errorf("statistical filter rule %d: file_pattern cannot be empty", i)
		}
		if rule.SeverityReduction < 0 || rule.SeverityReduction > 3 {
			return fmt.Errorf("statistical filter rule %d: severity_reduction must be 0-3", i)
		}
		if rule.ConfidenceReduction < 0 || rule.ConfidenceReduction > 3 {
			return fmt.Errorf("statistical filter rule %d: confidence_reduction must be 0-3", i)
		}
		if rule.Action != "" {
			validActions := map[string]bool{
				"ignore": true, "reduce_severity": true, "reduce_confidence": true,
			}
			if !validActions[rule.Action] {
				return fmt.Errorf("statistical filter rule %d: invalid action '%s'", i, rule.Action)
			}
		}
	}

	return nil
}
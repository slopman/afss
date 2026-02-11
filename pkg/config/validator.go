package config

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/security-scanner/afss-orchestrator/pkg/models"
)

// Validator validates configuration files
type Validator struct {
	logger *logrus.Logger
}

// NewValidator creates a new configuration validator
func NewValidator(logger *logrus.Logger) *Validator {
	return &Validator{logger: logger}
}

// ValidateOrchestratorConfig validates the main orchestrator configuration
func (v *Validator) ValidateOrchestratorConfig(config *models.OrchestratorConfig) error {
	if config.Version == "" {
		return fmt.Errorf("orchestrator config version is required")
	}

	// Validate global settings
	if config.Global.TimeoutSeconds <= 0 {
		return fmt.Errorf("global timeout_seconds must be positive")
	}

	// Validate resource settings
	if config.Resources.MaxParallelScans < 1 {
		return fmt.Errorf("max_parallel_scans must be at least 1")
	}

	if config.Resources.MemoryLimitPercent <= 0 || config.Resources.MemoryLimitPercent > 100 {
		return fmt.Errorf("memory_limit_percent must be between 1 and 100")
	}

	if config.Resources.CPULimitPercent <= 0 || config.Resources.CPULimitPercent > 100 {
		return fmt.Errorf("cpu_limit_percent must be between 1 and 100")
	}

	// Validate execution settings
	validModes := []string{"resource_aware", "parallel", "sequential"}
	if !v.contains(validModes, config.Execution.Mode) {
		return fmt.Errorf("execution mode must be one of: %v", validModes)
	}

	// Validate output settings
	validFormats := []string{"json", "sarif", "html"}
	if !v.contains(validFormats, config.Output.Format) {
		return fmt.Errorf("output format must be one of: %v", validFormats)
	}

	return nil
}

// ValidateToolConfig validates a tool configuration
func (v *Validator) ValidateToolConfig(config *models.ToolConfig) error {
	if config.Tool == "" {
		return fmt.Errorf("tool name is required")
	}

	if config.ResourceProfile.ToolName == "" {
		config.ResourceProfile.ToolName = config.Tool
	}

	// Validate resource profile
	if config.ResourceProfile.MemoryPeakMB < 0 {
		return fmt.Errorf("memory_peak_mb cannot be negative")
	}

	if config.ResourceProfile.CPUAvgPercent < 0 || config.ResourceProfile.CPUAvgPercent > 100 {
		return fmt.Errorf("cpu_avg_percent must be between 0 and 100")
	}

	// Validate CLI parameters
	if err := v.validateCLIParameters(config.Tool, config.CLI); err != nil {
		return fmt.Errorf("invalid CLI parameters: %w", err)
	}

	// Validate conditions
	for i, condition := range config.Conditions {
		if err := v.validateCondition(condition); err != nil {
			return fmt.Errorf("invalid condition %d: %w", i, err)
		}
	}

	return nil
}

// validateCLIParameters validates tool-specific CLI parameters
func (v *Validator) validateCLIParameters(toolName string, cli map[string]interface{}) error {
	switch toolName {
	case "gosec":
		return v.validateGosecCLI(cli)
	case "semgrep":
		return v.validateSemgrepCLI(cli)
	case "trufflehog":
		return v.validateTruffleHogCLI(cli)
	case "owasp-dep-check":
		return v.validateOWASPDepCheckCLI(cli)
	case "govulncheck":
		return v.validateGovulncheckCLI(cli)
	case "trivy":
		return v.validateTrivyCLI(cli)
	default:
		v.logger.Warn("No CLI validation for tool", "tool", toolName)
		return nil
	}
}

// validateGosecCLI validates Gosec CLI parameters
func (v *Validator) validateGosecCLI(cli map[string]interface{}) error {
	validSeverities := []string{"low", "medium", "high"}
	validConfidences := []string{"low", "medium", "high"}
	validFormats := []string{"json", "yaml", "csv", "junit-xml", "html", "sonarqube", "sarif", "text"}

	if severity, ok := cli["severity"].(string); ok {
		if !v.contains(validSeverities, severity) {
			return fmt.Errorf("invalid severity: %s", severity)
		}
	}

	if confidence, ok := cli["confidence"].(string); ok {
		if !v.contains(validConfidences, confidence) {
			return fmt.Errorf("invalid confidence: %s", confidence)
		}
	}

	if format, ok := cli["fmt"].(string); ok {
		if !v.contains(validFormats, format) {
			return fmt.Errorf("invalid fmt: %s", format)
		}
	}

	return nil
}

// validateSemgrepCLI validates Semgrep CLI parameters
func (v *Validator) validateSemgrepCLI(cli map[string]interface{}) error {
	if maxBytes, ok := cli["max_target_bytes"].(int); ok {
		if maxBytes < 0 {
			return fmt.Errorf("max_target_bytes cannot be negative")
		}
	}

	if jobs, ok := cli["jobs"].(int); ok {
		if jobs < 1 {
			return fmt.Errorf("jobs must be at least 1")
		}
	}

	if maxMemory, ok := cli["max_memory"].(int); ok {
		if maxMemory < 0 {
			return fmt.Errorf("max_memory cannot be negative")
		}
	}

	if timeout, ok := cli["timeout"].(float64); ok {
		if timeout <= 0 {
			return fmt.Errorf("timeout must be positive")
		}
	}

	if timeoutThreshold, ok := cli["timeout_threshold"].(int); ok {
		if timeoutThreshold < 0 {
			return fmt.Errorf("timeout_threshold cannot be negative")
		}
	}

	if interfileTimeout, ok := cli["interfile_timeout"].(int); ok {
		if interfileTimeout < 0 {
			return fmt.Errorf("interfile_timeout cannot be negative")
		}
	}

	if maxCharsPerLine, ok := cli["max_chars_per_line"].(int); ok {
		if maxCharsPerLine < 1 {
			return fmt.Errorf("max_chars_per_line must be at least 1")
		}
	}

	if maxLinesPerFinding, ok := cli["max_lines_per_finding"].(int); ok {
		if maxLinesPerFinding < 1 {
			return fmt.Errorf("max_lines_per_finding must be at least 1")
		}
	}

	if maxLogListEntries, ok := cli["max_log_list_entries"].(int); ok {
		if maxLogListEntries < 1 {
			return fmt.Errorf("max_log_list_entries must be at least 1")
		}
	}

	return nil
}


// validateCondition validates a condition
func (v *Validator) validateCondition(condition models.Condition) error {
	validTypes := []string{"file_exists", "not_file_exists", "is_git_repo"}

	if !v.contains(validTypes, condition.Type) {
		return fmt.Errorf("invalid condition type: %s", condition.Type)
	}

	if condition.Pattern == "" && condition.Type != "is_git_repo" {
		return fmt.Errorf("pattern is required for condition type: %s", condition.Type)
	}

	return nil
}

// validateOWASPDepCheckCLI validates OWASP Dependency Check CLI parameters
func (v *Validator) validateOWASPDepCheckCLI(cli map[string]interface{}) error {
	validFormats := []string{"HTML", "XML", "JSON", "CSV", "JUNIT", "SARIF", "ALL"}

	if format, ok := cli["format"].(string); ok {
		if !v.contains(validFormats, format) {
			return fmt.Errorf("invalid format: %s, valid: %v", format, validFormats)
		}
	}

	if failOnCVSS, ok := cli["failOnCVSS"].(int); ok {
		if failOnCVSS < 0 || failOnCVSS > 10 {
			return fmt.Errorf("failOnCVSS must be between 0 and 10")
		}
	}

	return nil
}

// validateGovulncheckCLI validates Govulncheck CLI parameters
func (v *Validator) validateGovulncheckCLI(cli map[string]interface{}) error {
	validFormats := []string{"text", "json", "sarif", "openvex"}
	validModes := []string{"source", "binary", "extract"}
	validScans := []string{"symbol", "package", "module"}
	validShows := []string{"traces", "color", "version", "verbose"}

	if format, ok := cli["format"].(string); ok {
		if !v.contains(validFormats, format) {
			return fmt.Errorf("invalid format: %s, valid: %v", format, validFormats)
		}
	}

	if mode, ok := cli["mode"].(string); ok {
		if !v.contains(validModes, mode) {
			return fmt.Errorf("invalid mode: %s, valid: %v", mode, validModes)
		}
	}

	if scan, ok := cli["scan"].(string); ok {
		if !v.contains(validScans, scan) {
			return fmt.Errorf("invalid scan level: %s, valid: %v", scan, validScans)
		}
	}

	if show, ok := cli["show"].([]interface{}); ok {
		for _, s := range show {
			if showStr, ok := s.(string); ok {
				if !v.contains(validShows, showStr) {
					return fmt.Errorf("invalid show option: %s, valid: %v", showStr, validShows)
				}
			}
		}
	}

	return nil
}

// validateTruffleHogCLI validates TruffleHog CLI parameters
func (v *Validator) validateTruffleHogCLI(cli map[string]interface{}) error {
	validResultTypes := []string{"verified", "unverified", "unknown", "filtered_unverified"}

	if results, ok := cli["results"].([]interface{}); ok {
		for _, r := range results {
			if resultStr, ok := r.(string); ok {
				if !v.contains(validResultTypes, resultStr) {
					return fmt.Errorf("invalid result type: %s, valid: %v", resultStr, validResultTypes)
				}
			}
		}
	}

	if filterEntropy, ok := cli["filter_entropy"].(float64); ok {
		if filterEntropy < 0 || filterEntropy > 8 {
			return fmt.Errorf("filter_entropy must be between 0 and 8")
		}
	}

	if logLevel, ok := cli["log_level"].(int); ok {
		if logLevel < 0 || logLevel > 5 {
			return fmt.Errorf("log_level must be between 0 and 5")
		}
	}

	return nil
}

// validateTrivyCLI validates Trivy CLI parameters
func (v *Validator) validateTrivyCLI(cli map[string]interface{}) error {
	validFormats := []string{"table", "json", "sarif", "cyclonedx", "spdx", "github", "junit"}
	validScanners := []string{"vuln", "secret", "misconfig", "license"}
	validTargets := []string{"filesystem", "image", "repository", "kubernetes", "sbom", "vm", "config", "rootfs"}

	if format, ok := cli["format"].(string); ok && format != "" {
		if !v.contains(validFormats, format) {
			return fmt.Errorf("invalid format: %s", format)
		}
	}

	if scanners, ok := cli["scanners"].([]interface{}); ok {
		for _, scanner := range scanners {
			if scannerStr, ok := scanner.(string); ok {
				if !v.contains(validScanners, scannerStr) {
					return fmt.Errorf("invalid scanner: %s", scannerStr)
				}
			}
		}
	}

	if target, ok := cli["target"].(string); ok && target != "" {
		if !v.contains(validTargets, target) {
			return fmt.Errorf("invalid target: %s", target)
		}
	}

	if timeout, ok := cli["timeout"].(string); ok && timeout != "" {
		// Basic validation for duration format
		if !strings.Contains(timeout, "m") && !strings.Contains(timeout, "s") && !strings.Contains(timeout, "h") {
			return fmt.Errorf("invalid timeout format: %s", timeout)
		}
	}

	if licenseConfidenceLevel, ok := cli["license_confidence_level"].(float64); ok {
		if licenseConfidenceLevel < 0 || licenseConfidenceLevel > 1 {
			return fmt.Errorf("license_confidence_level must be between 0 and 1")
		}
	}

	if exitCode, ok := cli["exit_code"].(int); ok {
		if exitCode < 0 {
			return fmt.Errorf("exit_code cannot be negative")
		}
	}

	if regoErrorLimit, ok := cli["rego_error_limit"].(int); ok {
		if regoErrorLimit < 0 {
			return fmt.Errorf("rego_error_limit cannot be negative")
		}
	}

	return nil
}

// contains checks if a slice contains a string
func (v *Validator) contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}
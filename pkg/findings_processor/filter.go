package findings_processor

import (
	"path/filepath"
	"strings"
)

// BasicFilter implements FilteringEngine
type BasicFilter struct{}

// NewBasicFilter creates a new basic filter
func NewBasicFilter() *BasicFilter {
	return &BasicFilter{}
}

// Filter applies filtering rules to remove noise and false positives
func (f *BasicFilter) Filter(findings []NormalizedFinding, config ProcessorConfig) ([]NormalizedFinding, error) {
	var filtered []NormalizedFinding

	for _, finding := range findings {
		if f.shouldInclude(finding, config) {
			filtered = append(filtered, finding)
		}
	}

	return filtered, nil
}

// shouldInclude determines if a finding should be included based on filter rules
func (f *BasicFilter) shouldInclude(finding NormalizedFinding, config ProcessorConfig) bool {
	// Severity filter
	if !f.isSeverityAtLeast(finding.Severity, config.Filtering.MinSeverity) {
		return false
	}

	// Confidence filter
	if !f.isConfidenceAtLeast(finding.Confidence, config.Filtering.MinConfidence) {
		return false
	}

	// Path filters
	if f.shouldExcludePath(finding.File, config.Filtering.ExcludePaths) {
		return false
	}

	if len(config.Filtering.IncludePaths) > 0 {
		if !f.shouldIncludePath(finding.File, config.Filtering.IncludePaths) {
			return false
		}
	}

	// Apply statistical filters (basic implementation)
	if f.isStatisticalFalsePositive(finding) {
		return false
	}

	return true
}

// shouldExcludePath checks if path should be excluded
func (f *BasicFilter) shouldExcludePath(filePath string, excludePaths []string) bool {
	for _, exclude := range excludePaths {
		if f.pathMatches(filePath, exclude) {
			return true
		}
	}
	return false
}

// shouldIncludePath checks if path should be included
func (f *BasicFilter) shouldIncludePath(filePath string, includePaths []string) bool {
	for _, include := range includePaths {
		if f.pathMatches(filePath, include) {
			return true
		}
	}
	return false
}

// pathMatches checks if file path matches pattern
func (f *BasicFilter) pathMatches(filePath, pattern string) bool {
	// Simple glob matching
	matched, err := filepath.Match(pattern, filePath)
	if err == nil && matched {
		return true
	}

	// Check if pattern is contained in path
	if strings.Contains(filePath, pattern) {
		return true
	}

	return false
}

// isStatisticalFalsePositive applies basic statistical filtering rules
func (f *BasicFilter) isStatisticalFalsePositive(finding NormalizedFinding) bool {
	// Test file patterns
	if f.isTestFile(finding.File) {
		// Reduce severity for test files
		if finding.Severity == High {
			finding.Severity = Medium
		} else if finding.Severity == Medium {
			finding.Severity = Low
		}
		// But don't completely exclude - just mark as processed
		finding.RawData["_test_file"] = true
	}

	// Generic API key patterns in config files
	if finding.Category == SecretFinding &&
	   strings.Contains(finding.Title, "Generic API Key") &&
	   f.isConfigFile(finding.File) {
		finding.RawData["_generic_secret_in_config"] = true
		// Don't exclude, but mark for review
	}

	// Generated file patterns
	if f.isGeneratedFile(finding.File) {
		finding.RawData["_generated_file"] = true
		// Reduce severity but don't exclude
		if finding.Severity == High {
			finding.Severity = Medium
		}
	}

	// Hardcoded credentials in test files - exclude
	if finding.Category == SecretFinding &&
	   f.isTestFile(finding.File) &&
	   (strings.Contains(finding.RuleID, "hardcoded") ||
	    strings.Contains(finding.RuleID, "generic-api-key")) {
		return true // Exclude
	}

	return false // Include
}

// isTestFile checks if file is a test file
func (f *BasicFilter) isTestFile(filePath string) bool {
	lowerPath := strings.ToLower(filePath)
	return strings.Contains(lowerPath, "test") ||
		   strings.Contains(lowerPath, "spec") ||
		   strings.HasSuffix(lowerPath, "_test.go") ||
		   strings.HasSuffix(lowerPath, ".test.js") ||
		   strings.HasSuffix(lowerPath, ".spec.ts")
}

// isConfigFile checks if file is a configuration file
func (f *BasicFilter) isConfigFile(filePath string) bool {
	lowerPath := strings.ToLower(filePath)
	return strings.HasSuffix(lowerPath, ".json") ||
		   strings.HasSuffix(lowerPath, ".yaml") ||
		   strings.HasSuffix(lowerPath, ".yml") ||
		   strings.HasSuffix(lowerPath, ".toml") ||
		   strings.HasSuffix(lowerPath, ".ini") ||
		   strings.Contains(lowerPath, "config") ||
		   strings.Contains(lowerPath, "settings")
}

// isSeverityAtLeast checks if finding severity meets minimum requirement
func (f *BasicFilter) isSeverityAtLeast(findingSeverity, minSeverity SeverityLevel) bool {
	severityOrder := map[SeverityLevel]int{
		Critical: 0,
		High:     1,
		Medium:   2,
		Low:      3,
		Info:     4,
	}

	findingLevel := severityOrder[findingSeverity]
	minLevel := severityOrder[minSeverity]

	return findingLevel <= minLevel // Lower number = higher severity
}

// isConfidenceAtLeast checks if finding confidence meets minimum requirement
func (f *BasicFilter) isConfidenceAtLeast(findingConfidence, minConfidence ConfidenceLevel) bool {
	confidenceOrder := map[ConfidenceLevel]int{
		Certain:  0,
		Likely:   1,
		Possible: 2,
	}

	findingLevel := confidenceOrder[findingConfidence]
	minLevel := confidenceOrder[minConfidence]

	return findingLevel <= minLevel // Lower number = higher confidence
}

// isGeneratedFile checks if file is generated
func (f *BasicFilter) isGeneratedFile(filePath string) bool {
	lowerPath := strings.ToLower(filePath)
	return strings.Contains(lowerPath, "generated") ||
		   strings.Contains(lowerPath, "auto") ||
		   strings.Contains(lowerPath, "migrations") ||
		   strings.HasSuffix(lowerPath, ".pb.go") ||
		   strings.HasPrefix(filepath.Base(lowerPath), ".")
}
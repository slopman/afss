package findings_processor

import (
	"regexp"
	"strings"
)

// StatisticalFilter implements advanced statistical filtering based on YAML rules
type StatisticalFilter struct {
	rules []StatisticalFilterRule
}

// NewStatisticalFilter creates a new statistical filter with the given rules
func NewStatisticalFilter(rules []StatisticalFilterRule) *StatisticalFilter {
	return &StatisticalFilter{
		rules: rules,
	}
}

// Filter applies statistical filtering rules to findings
func (sf *StatisticalFilter) Filter(findings []NormalizedFinding, config ProcessorConfig) ([]NormalizedFinding, error) {
	var filtered []NormalizedFinding

	for _, finding := range findings {
		processedFinding, shouldInclude := sf.applyRules(finding)

		// Update finding with processed version
		finding = processedFinding

		// Add metadata about applied rules
		if len(finding.RawData) == 0 {
			finding.RawData = make(map[string]interface{})
		}

		if shouldInclude {
			filtered = append(filtered, finding)
		}
	}

	return filtered, nil
}

// applyRules applies all statistical filtering rules to a single finding
func (sf *StatisticalFilter) applyRules(finding NormalizedFinding) (NormalizedFinding, bool) {
	appliedRules := []string{}

	for _, rule := range sf.rules {
		if sf.matchesRule(finding, rule) {
			appliedRules = append(appliedRules, rule.Reason)

			// Apply the rule action
			finding, include := sf.applyRuleAction(finding, rule)
			if !include {
				// Rule says to ignore this finding
				finding.RawData["_statistical_filter_ignored"] = true
				finding.RawData["_statistical_filter_rules"] = appliedRules
				return finding, false
			}
		}
	}

	// Mark applied rules for tracking
	if len(appliedRules) > 0 {
		finding.RawData["_statistical_filter_rules"] = appliedRules
	}

	return finding, true
}

// matchesRule checks if a finding matches a statistical filter rule
func (sf *StatisticalFilter) matchesRule(finding NormalizedFinding, rule StatisticalFilterRule) bool {
	// Check pattern match (against title, rule_id, description)
	patternMatched := sf.matchesPattern(finding, rule.Pattern)
	if !patternMatched {
		return false
	}

	// Check file pattern match
	fileMatched, err := sf.matchesFilePattern(finding.File, rule.FilePattern)
	if err != nil {
		// If regex is invalid, skip this rule
		return false
	}

	return fileMatched
}

// matchesPattern checks if finding matches the pattern (title, rule_id, or description)
func (sf *StatisticalFilter) matchesPattern(finding NormalizedFinding, pattern string) bool {
	// If pattern is ".*", match everything
	if pattern == ".*" {
		return true
	}

	// Try to compile regex
	re, err := regexp.Compile(pattern)
	if err != nil {
		// If regex is invalid, treat as literal string
		return sf.containsPattern(finding, pattern)
	}

	// Check against various fields
	fieldsToCheck := []string{
		finding.Title,
		finding.RuleID,
		finding.Description,
	}

	for _, field := range fieldsToCheck {
		if re.MatchString(field) {
			return true
		}
	}

	return false
}

// containsPattern checks if finding contains the pattern as substring
func (sf *StatisticalFilter) containsPattern(finding NormalizedFinding, pattern string) bool {
	fieldsToCheck := []string{
		finding.Title,
		finding.RuleID,
		finding.Description,
	}

	for _, field := range fieldsToCheck {
		if strings.Contains(field, pattern) {
			return true
		}
	}

	return false
}

// matchesFilePattern checks if file path matches the file pattern
func (sf *StatisticalFilter) matchesFilePattern(filePath, filePattern string) (bool, error) {
	// Convert glob patterns to regex
	regexPattern := sf.globToRegex(filePattern)

	re, err := regexp.Compile(regexPattern)
	if err != nil {
		return false, err
	}

	return re.MatchString(filePath), nil
}

// globToRegex converts a glob pattern to regex
func (sf *StatisticalFilter) globToRegex(pattern string) string {
	// Escape special regex characters except * and ?
	escaped := strings.ReplaceAll(pattern, ".", "\\.")
	escaped = strings.ReplaceAll(escaped, "+", "\\+")
	escaped = strings.ReplaceAll(escaped, "^", "\\^")
	escaped = strings.ReplaceAll(escaped, "$", "\\$")
	escaped = strings.ReplaceAll(escaped, "(", "\\(")
	escaped = strings.ReplaceAll(escaped, ")", "\\)")
	escaped = strings.ReplaceAll(escaped, "[", "\\[")
	escaped = strings.ReplaceAll(escaped, "]", "\\]")

	// Convert glob patterns
	escaped = strings.ReplaceAll(escaped, "*", ".*")
	escaped = strings.ReplaceAll(escaped, "?", ".")

	return "^" + escaped + "$"
}

// applyRuleAction applies the action specified in the rule
func (sf *StatisticalFilter) applyRuleAction(finding NormalizedFinding, rule StatisticalFilterRule) (NormalizedFinding, bool) {
	// If action is specified, use it
	if rule.Action != "" {
		switch rule.Action {
		case "ignore":
			return finding, false
		case "reduce_severity":
			finding = sf.reduceSeverity(finding, rule.ReductionLevel)
		case "reduce_confidence":
			finding = sf.reduceConfidence(finding, rule.ReductionLevel)
		}
		return finding, true
	}

	// Otherwise use the legacy severity_reduction and confidence_reduction
	if rule.SeverityReduction > 0 {
		finding = sf.reduceSeverity(finding, rule.SeverityReduction)
	}
	if rule.ConfidenceReduction > 0 {
		finding = sf.reduceConfidence(finding, rule.ConfidenceReduction)
	}

	return finding, true
}

// reduceSeverity reduces the severity of a finding by the specified levels
func (sf *StatisticalFilter) reduceSeverity(finding NormalizedFinding, levels int) NormalizedFinding {
	severityOrder := map[SeverityLevel]int{
		Critical: 0,
		High:     1,
		Medium:   2,
		Low:      3,
		Info:     4,
	}

	currentLevel := severityOrder[finding.Severity]
	newLevel := currentLevel + levels

	// Clamp to valid range
	if newLevel > 4 {
		newLevel = 4
	}

	// Convert back to SeverityLevel
	for sev, level := range severityOrder {
		if level == newLevel {
			finding.Severity = sev
			break
		}
	}

	// Add metadata
	finding.RawData["_severity_reduced_by"] = levels
	finding.RawData["_original_severity"] = finding.Severity

	return finding
}

// reduceConfidence reduces the confidence of a finding by the specified levels
func (sf *StatisticalFilter) reduceConfidence(finding NormalizedFinding, levels int) NormalizedFinding {
	confidenceOrder := map[ConfidenceLevel]int{
		Certain:  0,
		Likely:   1,
		Possible: 2,
	}

	currentLevel := confidenceOrder[finding.Confidence]
	newLevel := currentLevel + levels

	// Clamp to valid range
	if newLevel > 2 {
		newLevel = 2
	}

	// Convert back to ConfidenceLevel
	for conf, level := range confidenceOrder {
		if level == newLevel {
			finding.Confidence = conf
			break
		}
	}

	// Add metadata
	finding.RawData["_confidence_reduced_by"] = levels
	finding.RawData["_original_confidence"] = finding.Confidence

	return finding
}
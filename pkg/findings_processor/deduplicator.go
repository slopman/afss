package findings_processor

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// AggressiveDeduplicator implements DeduplicationEngine with code hashing
type AggressiveDeduplicator struct {
	config ProcessorConfig
}

// NewAggressiveDeduplicator creates a new aggressive deduplicator
func NewAggressiveDeduplicator(config ProcessorConfig) *AggressiveDeduplicator {
	return &AggressiveDeduplicator{config: config}
}

// Deduplicate removes duplicate findings using aggressive hashing
func (d *AggressiveDeduplicator) Deduplicate(findings []NormalizedFinding) ([]NormalizedFinding, error) {
	if !d.config.EnableDeduplication {
		return findings, nil
	}

	groups := make(map[string][]NormalizedFinding)

	// Group findings by deduplication key
	for _, finding := range findings {
		key := d.createGroupingKey(finding)
		groups[key] = append(groups[key], finding)
	}

	var deduplicated []NormalizedFinding

	// Merge groups
	for _, group := range groups {
		if len(group) == 1 {
			deduplicated = append(deduplicated, group[0])
		} else {
			merged := d.mergeGroup(group)
			deduplicated = append(deduplicated, merged)
		}
	}

	return deduplicated, nil
}

// createGroupingKey creates a deduplication key using File:Line:CWE:CodeHash
func (d *AggressiveDeduplicator) createGroupingKey(finding NormalizedFinding) string {
	// Normalize code snippet with aggressive whitespace stripping
	normalizedCode := d.normalizeCodeSnippet(finding.CodeSnippet)
	codeHash := d.hashCode(normalizedCode)

	// Sort CWE for consistent ordering
	cweStr := ""
	if len(finding.CWE) > 0 {
		sortedCWE := make([]string, len(finding.CWE))
		copy(sortedCWE, finding.CWE)
		sort.Strings(sortedCWE)
		cweStr = strings.Join(sortedCWE, ",")
	}

	// Create key: File:Line:RuleID:CWE:CodeHash
	key := fmt.Sprintf("%s:%d:%s:%s:%s",
		finding.File,
		finding.Line,
		finding.RuleID,
		cweStr,
		codeHash)

	return key
}

// normalizeCodeSnippet performs aggressive normalization for deduplication
func (d *AggressiveDeduplicator) normalizeCodeSnippet(code string) string {
	if code == "" {
		return ""
	}

	// 1. Remove comments first (before whitespace normalization)
	code = d.removeComments(code)

	// 2. Aggressive whitespace stripping - remove ALL spaces, tabs, newlines
	var result strings.Builder
	for _, r := range code {
		if !unicode.IsSpace(r) {
			result.WriteRune(r)
		}
	}

	// 3. Normalize to lowercase for case-insensitive matching
	normalized := strings.ToLower(result.String())

	// 4. Remove empty strings
	if normalized == "" {
		return ""
	}

	return normalized
}

// removeComments removes comments from code for better deduplication
func (d *AggressiveDeduplicator) removeComments(code string) string {
	lines := strings.Split(code, "\n")
	var cleaned []string

	for _, line := range lines {
		// Remove single-line comments
		if idx := strings.Index(line, "//"); idx != -1 {
			line = line[:idx]
		}
		if idx := strings.Index(line, "#"); idx != -1 {
			line = line[:idx]
		}

		// Remove C-style comments (simple implementation)
		re := regexp.MustCompile(`/\*.*?\*/`)
		line = re.ReplaceAllString(line, "")

		// Trim and keep non-empty lines
		line = strings.TrimSpace(line)
		if line != "" {
			cleaned = append(cleaned, line)
		}
	}

	return strings.Join(cleaned, "\n")
}

// hashCode creates a hash of the normalized code
func (d *AggressiveDeduplicator) hashCode(code string) string {
	hashLength := d.config.Deduplication.CodeHashLength
	if hashLength <= 0 {
		hashLength = 8 // Default
	}

	hash := sha256.Sum256([]byte(code))
	return fmt.Sprintf("%x", hash)[:hashLength]
}

// mergeGroup merges a group of duplicate findings into one
func (d *AggressiveDeduplicator) mergeGroup(group []NormalizedFinding) NormalizedFinding {
	if len(group) == 0 {
		return NormalizedFinding{}
	}

	// Sort by severity (Critical first)
	sort.Slice(group, func(i, j int) bool {
		severityOrder := map[SeverityLevel]int{
			Critical: 0,
			High:     1,
			Medium:   2,
			Low:      3,
			Info:     4,
		}
		return severityOrder[group[i].Severity] < severityOrder[group[j].Severity]
	})

	// Take the finding with highest severity as base
	merged := group[0]

	// Collect all tools that detected this finding
	tools := make(map[string]bool)
	for _, finding := range group {
		tools[finding.Tool] = true
	}

	toolList := make([]string, 0, len(tools))
	for tool := range tools {
		toolList = append(toolList, tool)
	}

	// Add metadata about deduplication
	if merged.RawData == nil {
		merged.RawData = make(map[string]interface{})
	}
	merged.RawData["_duplicate_count"] = len(group)
	merged.RawData["_duplicate_tools"] = toolList
	merged.RawData["_deduplication_key"] = d.createGroupingKey(merged)

	// Update tool field if multiple tools
	if len(toolList) > 1 {
		merged.Tool = toolList[0] // Primary tool
		merged.RawData["_detected_by"] = toolList
	}

	// Aggregate confidence (take the highest)
	confidenceOrder := map[ConfidenceLevel]int{
		Certain:  0,
		Likely:   1,
		Possible: 2,
	}

	maxConfidence := Possible
	for _, finding := range group {
		if confidenceOrder[finding.Confidence] < confidenceOrder[maxConfidence] {
			maxConfidence = finding.Confidence
		}
	}
	merged.Confidence = maxConfidence

	return merged
}
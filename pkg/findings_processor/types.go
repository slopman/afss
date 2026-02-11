package findings_processor

import (
	"time"
)

// SeverityLevel represents the severity of a finding
type SeverityLevel string

const (
	Critical SeverityLevel = "Critical"
	High     SeverityLevel = "High"
	Medium   SeverityLevel = "Medium"
	Low      SeverityLevel = "Low"
	Info     SeverityLevel = "Info"
)

// ConfidenceLevel represents the confidence in the finding
type ConfidenceLevel string

const (
	Certain  ConfidenceLevel = "Certain"
	Likely   ConfidenceLevel = "Likely"
	Possible ConfidenceLevel = "Possible"
)

// FindingCategory represents the category of the finding
type FindingCategory string

const (
	CodeFinding    FindingCategory = "code"
	VulnFinding    FindingCategory = "vuln"
	SecretFinding  FindingCategory = "secret"
	ConfigFinding  FindingCategory = "config"
	UnknownFinding FindingCategory = "unknown"
)

// NormalizedFinding represents a normalized security finding
type NormalizedFinding struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Severity    SeverityLevel          `json:"severity"`
	Confidence  ConfidenceLevel        `json:"confidence"`
	Category    FindingCategory        `json:"category"`
	Tool        string                 `json:"tool"`
	File        string                 `json:"file"`
	Line        int                    `json:"line"`
	CodeSnippet string                 `json:"code_snippet"`
	RuleID      string                 `json:"rule_id"`
	Tags        []string               `json:"tags"`
	RawData     map[string]interface{} `json:"raw_data"`

	// Normalized fields
	CWE         []string               `json:"cwe"`
	CVSS        *CVSSScore             `json:"cvss"`
	References  []string               `json:"references"`
	Fix         *FixSuggestion         `json:"fix"`

	// Processing metadata
	Timestamp   time.Time              `json:"timestamp"`
	Processed   bool                   `json:"processed"`
}

// CVSSScore represents CVSS scoring
type CVSSScore struct {
	Version string  `json:"version"`
	Vector  string  `json:"vector"`
	BaseScore float64 `json:"base_score"`
	Severity string  `json:"severity"`
}

// FixSuggestion represents a suggested fix
type FixSuggestion struct {
	Description string   `json:"description"`
	Code        string   `json:"code"`
	References  []string `json:"references"`
}

// StatisticalFilterRule represents a single statistical filtering rule
type StatisticalFilterRule struct {
	Pattern             string `yaml:"pattern"`              // Regex pattern for finding (title, rule_id, etc.)
	FilePattern         string `yaml:"file_pattern"`         // Regex pattern for file path
	SeverityReduction   int    `yaml:"severity_reduction"`   // Reduce severity by N levels (0-3)
	ConfidenceReduction int    `yaml:"confidence_reduction"` // Reduce confidence by N levels (0-3)
	Action              string `yaml:"action"`               // Alternative: "ignore", "reduce_severity", "reduce_confidence"
	ReductionLevel      int    `yaml:"reduction_level"`      // For action-based rules
	Reason              string `yaml:"reason"`               // Why this rule exists
}

// FindingsProcessorConfig represents the root configuration for findings processor
type FindingsProcessorConfig struct {
	FindingsProcessor ProcessorConfig `yaml:"findings_processor"`
}

// ProcessorConfig represents configuration for the findings processor
type ProcessorConfig struct {
	EnableNormalizer    bool `yaml:"enable_normalizer"`
	EnableDeduplication bool `yaml:"enable_deduplication"`
	EnableCorrelation   bool `yaml:"enable_correlation"`
	EnableFiltering     bool `yaml:"enable_filtering"`
	EnableScoring       bool `yaml:"enable_scoring"`

	// Deduplication settings
	Deduplication struct {
		EnableAggressiveHashing bool `yaml:"enable_aggressive_hashing"`
		CodeHashLength         int  `yaml:"code_hash_length"`
	} `yaml:"deduplication"`

	// Filtering settings
	Filtering struct {
		MinSeverity       SeverityLevel            `yaml:"min_severity"`
		MinConfidence     ConfidenceLevel          `yaml:"min_confidence"`
		ExcludePaths      []string                 `yaml:"exclude_paths"`
		IncludePaths      []string                 `yaml:"include_paths"`
		StatisticalFilters []StatisticalFilterRule `yaml:"statistical_filters"`
	} `yaml:"filtering"`

	// Prioritization settings
	Prioritization struct {
		Enabled bool `yaml:"enabled"`
		BusinessContext struct {
			CriticalPaths []string `yaml:"critical_paths"`
			DataSensitivity struct {
				High   []string `yaml:"high"`
				Medium []string `yaml:"medium"`
			} `yaml:"data_sensitivity"`
		} `yaml:"business_context"`
	} `yaml:"prioritization"`

	// Output settings
	Output struct {
		Formats      []string `yaml:"formats"`
		MaxFindings  int      `yaml:"max_findings"`
		GroupBy      string   `yaml:"group_by"`
		IncludeMetadata bool  `yaml:"include_metadata"`
		IncludeCorrelations bool `yaml:"include_correlations"`
	} `yaml:"output"`

	// Deduplication settings from YAML
	DeduplicationConfig struct {
		Enabled           bool    `yaml:"enabled"`
		SimilarityThreshold float64 `yaml:"similarity_threshold"`
		AggressiveNormalization bool `yaml:"aggressive_normalization"`
	} `yaml:"deduplication_config"`
}
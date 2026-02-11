package findings_processor

import (
	"fmt"
	"time"
)

// FindingsProcessorImpl implements FindingsProcessor
type FindingsProcessorImpl struct {
	pipeline *ProcessingPipeline
}

// NewFindingsProcessor creates a new findings processor
func NewFindingsProcessor(config ProcessorConfig) *FindingsProcessorImpl {
	// Create combined filter with basic + statistical filtering
	var filter FilteringEngine = NewBasicFilter()

	// If statistical filters are configured, wrap with statistical filter
	if len(config.Filtering.StatisticalFilters) > 0 {
		statisticalFilter := NewStatisticalFilter(config.Filtering.StatisticalFilters)
		filter = NewCombinedFilter(NewBasicFilter(), statisticalFilter)
	}

	pipeline := &ProcessingPipeline{
		Normalizer:   NewDefaultNormalizer(),
		Deduplicator: NewAggressiveDeduplicator(config),
		Correlator:   NewBasicCorrelator(),
		Filter:       filter,
		Config:       config,
	}

	return &FindingsProcessorImpl{
		pipeline: pipeline,
	}
}

// Process executes the full processing pipeline on raw findings
func (p *FindingsProcessorImpl) Process(rawFindings []interface{}) ([]NormalizedFinding, []Correlation, error) {
	start := time.Now()

	// Execute pipeline
	normalized, correlations, err := p.pipeline.Process(rawFindings)
	if err != nil {
		return nil, nil, fmt.Errorf("pipeline processing failed: %w", err)
	}

	elapsed := time.Since(start)
	fmt.Printf("Findings Processor completed in %v\n", elapsed)
	fmt.Printf("Processed %d raw findings into %d normalized findings\n", len(rawFindings), len(normalized))
	fmt.Printf("Found %d correlations\n", len(correlations))

	return normalized, correlations, nil
}

// ProcessNormalized executes filtering pipeline on already normalized findings
func (p *FindingsProcessorImpl) ProcessNormalized(findings []NormalizedFinding) ([]NormalizedFinding, []Correlation, error) {
	start := time.Now()

	// Apply deduplication
	if p.pipeline.Config.EnableDeduplication && p.pipeline.Deduplicator != nil {
		var err error
		findings, err = p.pipeline.Deduplicator.Deduplicate(findings)
		if err != nil {
			return nil, nil, fmt.Errorf("deduplication failed: %w", err)
		}
	}

	// Apply correlation
	var correlations []Correlation
	if p.pipeline.Config.EnableCorrelation && p.pipeline.Correlator != nil {
		var err error
		correlations, err = p.pipeline.Correlator.Correlate(findings)
		if err != nil {
			return nil, nil, fmt.Errorf("correlation failed: %w", err)
		}
	}

	// Apply filtering
	if p.pipeline.Config.EnableFiltering && p.pipeline.Filter != nil {
		var err error
		findings, err = p.pipeline.Filter.Filter(findings, p.pipeline.Config)
		if err != nil {
			return nil, nil, fmt.Errorf("filtering failed: %w", err)
		}
	}

	elapsed := time.Since(start)
	fmt.Printf("Findings Processor completed in %v\n", elapsed)
	fmt.Printf("Processed %d normalized findings into %d final findings\n", len(findings), len(findings))
	fmt.Printf("Found %d correlations\n", len(correlations))

	return findings, correlations, nil
}

// GetPipeline returns the processing pipeline for inspection
func (p *FindingsProcessorImpl) GetPipeline() *ProcessingPipeline {
	return p.pipeline
}

// DefaultConfig returns a default processor configuration
func DefaultConfig() ProcessorConfig {
	return ProcessorConfig{
		EnableNormalizer:    true,
		EnableDeduplication: true,
		EnableCorrelation:   true,
		EnableFiltering:     true,
		EnableScoring:       false, // Not implemented yet
		Deduplication: struct {
			EnableAggressiveHashing bool `yaml:"enable_aggressive_hashing"`
			CodeHashLength         int  `yaml:"code_hash_length"`
		}{
			EnableAggressiveHashing: true,
			CodeHashLength:         8,
		},
		Filtering: struct {
			MinSeverity       SeverityLevel            `yaml:"min_severity"`
			MinConfidence     ConfidenceLevel          `yaml:"min_confidence"`
			ExcludePaths      []string                 `yaml:"exclude_paths"`
			IncludePaths      []string                 `yaml:"include_paths"`
			StatisticalFilters []StatisticalFilterRule `yaml:"statistical_filters"`
		}{
			MinSeverity:   Info,
			MinConfidence: Possible,
			ExcludePaths: []string{
				"**/node_modules/**",
				"**/vendor/**",
				"**/.git/**",
				"**/dist/**",
				"**/build/**",
			},
			StatisticalFilters: []StatisticalFilterRule{}, // Empty by default
		},
	}
}
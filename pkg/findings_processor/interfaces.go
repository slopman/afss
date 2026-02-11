package findings_processor

// FindingsProcessor defines the main interface for processing security findings
type FindingsProcessor interface {
	Process(rawFindings []interface{}) ([]NormalizedFinding, []Correlation, error)
	ProcessNormalized(findings []NormalizedFinding) ([]NormalizedFinding, []Correlation, error)
}

// FindingsNormalizer normalizes raw tool findings into standardized format
type FindingsNormalizer interface {
	Normalize(rawFindings []interface{}) ([]NormalizedFinding, error)
}

// DeduplicationEngine removes duplicate findings
type DeduplicationEngine interface {
	Deduplicate(findings []NormalizedFinding) ([]NormalizedFinding, error)
}

// CorrelationEngine finds relationships between findings
type CorrelationEngine interface {
	Correlate(findings []NormalizedFinding) ([]Correlation, error)
}

// FilteringEngine filters out noise and false positives
type FilteringEngine interface {
	Filter(findings []NormalizedFinding, config ProcessorConfig) ([]NormalizedFinding, error)
}

// ScoringEngine calculates relevance scores for findings
type ScoringEngine interface {
	Score(findings []NormalizedFinding) ([]NormalizedFinding, error)
}

// PrioritizationEngine ranks findings by business impact
type PrioritizationEngine interface {
	Prioritize(findings []NormalizedFinding) ([]NormalizedFinding, error)
}

// Correlation represents a relationship between findings
type Correlation struct {
	ID          string                 `json:"id"`
	Type        CorrelationType        `json:"type"`
	Findings    []string               `json:"finding_ids"`
	Strength    float64                `json:"strength"`
	Description string                 `json:"description"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// CorrelationType represents different types of correlations
type CorrelationType string

const (
	SameVulnerability     CorrelationType = "same_vuln"
	RelatedVulnerability  CorrelationType = "related_vuln"
	SameFile             CorrelationType = "same_file"
	SamePackage          CorrelationType = "same_package"
	DependencyChain      CorrelationType = "dependency_chain"
)

// ProcessingPipeline represents the complete processing pipeline
type ProcessingPipeline struct {
	Normalizer     FindingsNormalizer
	Deduplicator   DeduplicationEngine
	Correlator     CorrelationEngine
	Filter         FilteringEngine
	Scorer         ScoringEngine
	Prioritizer    PrioritizationEngine
	Config         ProcessorConfig
}

// Process executes the full processing pipeline
func (p *ProcessingPipeline) Process(rawFindings []interface{}) ([]NormalizedFinding, []Correlation, error) {
	var normalized []NormalizedFinding
	var correlations []Correlation
	var err error

	// 1. Normalization
	if p.Config.EnableNormalizer && p.Normalizer != nil {
		normalized, err = p.Normalizer.Normalize(rawFindings)
		if err != nil {
			return nil, nil, err
		}
	}

	// 2. Deduplication
	if p.Config.EnableDeduplication && p.Deduplicator != nil {
		normalized, err = p.Deduplicator.Deduplicate(normalized)
		if err != nil {
			return nil, nil, err
		}
	}

	// 3. Correlation
	if p.Config.EnableCorrelation && p.Correlator != nil {
		correlations, err = p.Correlator.Correlate(normalized)
		if err != nil {
			return nil, nil, err
		}
	}

	// 4. Filtering
	if p.Config.EnableFiltering && p.Filter != nil {
		normalized, err = p.Filter.Filter(normalized, p.Config)
		if err != nil {
			return nil, nil, err
		}
	}

	// 5. Scoring
	if p.Config.EnableScoring && p.Scorer != nil {
		normalized, err = p.Scorer.Score(normalized)
		if err != nil {
			return nil, nil, err
		}
	}

	return normalized, correlations, nil
}
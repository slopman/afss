package findings_processor

// CombinedFilter combines multiple filtering engines
type CombinedFilter struct {
	filters []FilteringEngine
}

// NewCombinedFilter creates a new combined filter with multiple filtering engines
func NewCombinedFilter(filters ...FilteringEngine) *CombinedFilter {
	return &CombinedFilter{
		filters: filters,
	}
}

// Filter applies all filtering engines in sequence
func (cf *CombinedFilter) Filter(findings []NormalizedFinding, config ProcessorConfig) ([]NormalizedFinding, error) {
	currentFindings := findings

	// Apply each filter in sequence
	for _, filter := range cf.filters {
		if filter != nil {
			filtered, err := filter.Filter(currentFindings, config)
			if err != nil {
				return nil, err
			}
			currentFindings = filtered
		}
	}

	return currentFindings, nil
}
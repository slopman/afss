package normalizers

import (
	"github.com/security-scanner/afss-orchestrator/pkg/findings_processor"
)

// ToolNormalizer defines the interface for tool-specific normalizers
type ToolNormalizer interface {
	// Normalize converts tool-specific raw results into normalized findings
	Normalize(rawData []byte) ([]findings_processor.NormalizedFinding, error)

	// CanHandle checks if this normalizer can handle the given tool output
	CanHandle(rawData []byte) bool

	// ToolName returns the name of the tool this normalizer handles
	ToolName() string
}

// NormalizerFactory creates normalizers for different tools
type NormalizerFactory struct {
	normalizers map[string]ToolNormalizer
}

// NewNormalizerFactory creates a new factory
func NewNormalizerFactory() *NormalizerFactory {
	factory := &NormalizerFactory{
		normalizers: make(map[string]ToolNormalizer),
	}

	// Register all available normalizers
	factory.registerNormalizers()

	return factory
}

// GetNormalizer returns the appropriate normalizer for the given raw data
func (f *NormalizerFactory) GetNormalizer(rawData []byte) ToolNormalizer {
	for _, normalizer := range f.normalizers {
		if normalizer.CanHandle(rawData) {
			return normalizer
		}
	}
	return nil
}

// GetNormalizerByTool returns normalizer by tool name
func (f *NormalizerFactory) GetNormalizerByTool(toolName string) ToolNormalizer {
	return f.normalizers[toolName]
}

// registerNormalizers registers all available normalizers
func (f *NormalizerFactory) registerNormalizers() {
	f.normalizers["bandit"] = NewBanditNormalizer()
	f.normalizers["gitleaks"] = NewGitleaksNormalizer()
	f.normalizers["trivy"] = NewTrivyNormalizer()
	f.normalizers["semgrep"] = NewSemgrepNormalizer()
	f.normalizers["gosec"] = NewGosecNormalizer()
	f.normalizers["njsscan"] = NewNjsscanNormalizer()
	f.normalizers["hadolint"] = NewHadolintNormalizer()
	f.normalizers["osv"] = NewOSVNormalizer()
	f.normalizers["govulncheck"] = NewGovulncheckNormalizer()
	f.normalizers["checkov"] = NewCheckovNormalizer()
	f.normalizers["trufflehog"] = NewTruffleHogNormalizer()
}
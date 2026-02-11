package normalizers

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/security-scanner/afss-orchestrator/pkg/findings_processor"
)

// ResultsAggregator combines normalized findings from multiple tools
type ResultsAggregator struct {
	factory *NormalizerFactory
}

// NewResultsAggregator creates a new results aggregator
func NewResultsAggregator() *ResultsAggregator {
	return &ResultsAggregator{
		factory: NewNormalizerFactory(),
	}
}

// ProcessToolResults processes results from a specific tool
func (ra *ResultsAggregator) ProcessToolResults(toolName, inputFile, outputDir string) error {
	// Read input file
	rawData, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read input file %s: %w", inputFile, err)
	}

	// Get normalizer for this tool
	normalizer := ra.factory.GetNormalizerByTool(toolName)
	if normalizer == nil {
		return fmt.Errorf("no normalizer found for tool: %s", toolName)
	}

	// Normalize the data
	findings, err := normalizer.Normalize(rawData)
	if err != nil {
		return fmt.Errorf("normalization failed for %s: %w", toolName, err)
	}

	// Save normalized results
	outputFile := fmt.Sprintf("%s/%s_normalized.json", outputDir, toolName)
	if err := ra.saveFindings(findings, outputFile); err != nil {
		return fmt.Errorf("failed to save results for %s: %w", toolName, err)
	}

	fmt.Printf("✅ %s: %d findings → %s\n", toolName, len(findings), outputFile)
	return nil
}

// AggregateResults combines all normalized results into final findings array
func (ra *ResultsAggregator) AggregateResults(inputDir, outputFile string) error {
	// Read all normalized JSON files from input directory
	entries, err := os.ReadDir(inputDir)
	if err != nil {
		return fmt.Errorf("failed to read input directory: %w", err)
	}

	var allFindings []findings_processor.NormalizedFinding

	for _, entry := range entries {
		if entry.IsDir() || !ra.isNormalizedFile(entry.Name()) {
			continue
		}

		filePath := fmt.Sprintf("%s/%s", inputDir, entry.Name())
		findings, err := ra.loadFindings(filePath)
		if err != nil {
			fmt.Printf("⚠️  Warning: failed to load %s: %v\n", filePath, err)
			continue
		}

		allFindings = append(allFindings, findings...)
		fmt.Printf("📥 Loaded %d findings from %s\n", len(findings), entry.Name())
	}

	// Save aggregated results
	if err := ra.saveFindings(allFindings, outputFile); err != nil {
		return fmt.Errorf("failed to save aggregated results: %w", err)
	}

	fmt.Printf("✅ Aggregated %d total findings → %s\n", len(allFindings), outputFile)
	return nil
}

// AutoProcess automatically detects tool and processes results
func (ra *ResultsAggregator) AutoProcess(inputFile, outputDir string) error {
	// Read input file
	rawData, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	// Auto-detect normalizer
	normalizer := ra.factory.GetNormalizer(rawData)
	if normalizer == nil {
		return fmt.Errorf("no normalizer found for this tool output")
	}

	fmt.Printf("🔍 Auto-detected tool: %s\n", normalizer.ToolName())

	// Normalize the data
	findings, err := normalizer.Normalize(rawData)
	if err != nil {
		return fmt.Errorf("normalization failed: %w", err)
	}

	// Save normalized results
	outputFile := fmt.Sprintf("%s/%s_normalized.json", outputDir, normalizer.ToolName())
	if err := ra.saveFindings(findings, outputFile); err != nil {
		return fmt.Errorf("failed to save results: %w", err)
	}

	fmt.Printf("✅ %s: %d findings → %s\n", normalizer.ToolName(), len(findings), outputFile)
	return nil
}

// Helper methods

func (ra *ResultsAggregator) isNormalizedFile(filename string) bool {
	// Check if file contains "_normalized.json"
	return strings.Contains(filename, "_normalized.json")
}

func (ra *ResultsAggregator) saveFindings(findings []findings_processor.NormalizedFinding, outputFile string) error {
	file, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(findings)
}

func (ra *ResultsAggregator) loadFindings(inputFile string) ([]findings_processor.NormalizedFinding, error) {
	file, err := os.Open(inputFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var findings []findings_processor.NormalizedFinding
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&findings)
	return findings, err
}
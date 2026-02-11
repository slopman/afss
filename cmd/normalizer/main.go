package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/security-scanner/afss-orchestrator/pkg/findings_processor"
	"github.com/security-scanner/afss-orchestrator/pkg/normalizers"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: normalizer <input_file.json>")
		fmt.Println("Normalizes tool output to standardized findings format")
		os.Exit(1)
	}

	inputFile := os.Args[1]

	// Read input file
	rawData, err := os.ReadFile(inputFile)
	if err != nil {
		log.Fatalf("Failed to read input file: %v", err)
	}

	// Create normalizer factory
	factory := normalizers.NewNormalizerFactory()

	// Find appropriate normalizer
	normalizer := factory.GetNormalizer(rawData)
	if normalizer == nil {
		log.Fatalf("No normalizer found for this tool output")
	}

	fmt.Printf("Using %s normalizer\n", normalizer.ToolName())

	// Normalize the data
	findings, err := normalizer.Normalize(rawData)
	if err != nil {
		log.Fatalf("Normalization failed: %v", err)
	}

	fmt.Printf("Normalized %d findings\n", len(findings))

	// Save results
	outputFile := "normalized_findings.json"
	file, err := os.Create(outputFile)
	if err != nil {
		log.Fatalf("Failed to create output file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(findings); err != nil {
		log.Fatalf("Failed to write results: %v", err)
	}

	fmt.Printf("✅ Results saved to: %s\n", outputFile)

	// Show summary
	showSummaryNormalized(findings)
}

func showSummaryNormalized(findings []findings_processor.NormalizedFinding) {
	fmt.Println("\n📋 SUMMARY:")

	if len(findings) == 0 {
		fmt.Println("No findings")
		return
	}

	// Count by severity
	severityCount := make(map[findings_processor.SeverityLevel]int)
	categoryCount := make(map[findings_processor.FindingCategory]int)

	for _, f := range findings {
		severityCount[f.Severity]++
		categoryCount[f.Category]++
	}

	fmt.Printf("🔧 Tool: %s\n", findings[0].Tool)
	fmt.Printf("📈 Total findings: %d\n", len(findings))

	fmt.Println("🔥 By Severity:")
	for sev, count := range severityCount {
		fmt.Printf("  %s: %d\n", sev, count)
	}

	fmt.Println("📂 By Category:")
	for cat, count := range categoryCount {
		fmt.Printf("  %s: %d\n", cat, count)
	}
}
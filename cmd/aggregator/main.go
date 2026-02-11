package main

import (
	"fmt"
	"log"
	"os"

	"github.com/security-scanner/afss-orchestrator/pkg/normalizers"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	aggregator := normalizers.NewResultsAggregator()

	switch command {
	case "auto":
		if len(os.Args) < 4 {
			fmt.Println("Usage: aggregator auto <input_file> <output_dir>")
			os.Exit(1)
		}
		inputFile := os.Args[2]
		outputDir := os.Args[3]

		if err := aggregator.AutoProcess(inputFile, outputDir); err != nil {
			log.Fatalf("Auto processing failed: %v", err)
		}

	case "tool":
		if len(os.Args) < 5 {
			fmt.Println("Usage: aggregator tool <tool_name> <input_file> <output_dir>")
			os.Exit(1)
		}
		toolName := os.Args[2]
		inputFile := os.Args[3]
		outputDir := os.Args[4]

		if err := aggregator.ProcessToolResults(toolName, inputFile, outputDir); err != nil {
			log.Fatalf("Tool processing failed: %v", err)
		}

	case "aggregate":
		if len(os.Args) < 4 {
			fmt.Println("Usage: aggregator aggregate <input_dir> <output_file>")
			os.Exit(1)
		}
		inputDir := os.Args[2]
		outputFile := os.Args[3]

		if err := aggregator.AggregateResults(inputDir, outputFile); err != nil {
			log.Fatalf("Aggregation failed: %v", err)
		}

	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("🔧 Findings Normalizer & Aggregator")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("  aggregator auto <input_file> <output_dir>     - Auto-detect tool and normalize")
	fmt.Println("  aggregator tool <tool_name> <input_file> <output_dir> - Process specific tool")
	fmt.Println("  aggregator aggregate <input_dir> <output_file> - Combine all normalized results")
	fmt.Println("")
	fmt.Println("Supported tools: bandit, gitleaks, trivy, semgrep, gosec, osv")
	fmt.Println("")
	fmt.Println("Examples:")
	fmt.Println("  aggregator auto results/bandit.json normalized/")
	fmt.Println("  aggregator tool bandit results/bandit.json normalized/")
	fmt.Println("  aggregator aggregate normalized/ final_findings.json")
}
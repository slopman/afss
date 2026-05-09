package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/security-scanner/afss-orchestrator/pkg/findings_processor"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: findings_processor <input_file.json>")
		os.Exit(1)
	}

	inputFile := os.Args[1]

	// Load input data as bytes first
	inputData, err := os.ReadFile(inputFile)
	if err != nil {
		log.Fatalf("Failed to read input file: %v", err)
	}

	// Load processor configuration
	configLoader := findings_processor.NewConfigLoader()
	config, err := configLoader.LoadDefaultConfig()
	if err != nil {
		log.Fatalf("Failed to load processor config: %v", err)
	}

	fmt.Printf("Loaded configuration with %d statistical filters\n", len(config.Filtering.StatisticalFilters))

	processor := findings_processor.NewFindingsProcessor(*config)

	var normalized []findings_processor.NormalizedFinding
	var inputCount int

	// Check if input is already normalized JSON
	var normalizedFindings []findings_processor.NormalizedFinding
	if err := json.Unmarshal(inputData, &normalizedFindings); err == nil && len(normalizedFindings) > 0 && normalizedFindings[0].ID != "" {
		// Input is already normalized findings
		fmt.Printf("Processing %d normalized findings...\n", len(normalizedFindings))
		inputCount = len(normalizedFindings)
		normalized, _, err = processor.ProcessNormalized(normalizedFindings)
	} else {
		// Load as raw tool data
		data, err := loadJSONFile(inputFile)
		if err != nil {
			log.Fatalf("Failed to load input file: %v", err)
		}
		fmt.Printf("Processing %d raw findings...\n", len(data))
		inputCount = len(data)
		normalized, _, err = processor.Process(data)
	}

	if err != nil {
		log.Fatalf("Processing failed: %v", err)
	}

	// Save results
	outputFile := "processed_findings.json"
	err = saveJSONFile(outputFile, normalized)
	if err != nil {
		log.Fatalf("Failed to save results: %v", err)
	}

	fmt.Printf("✅ Processing complete!\n")
	fmt.Printf("📊 Results saved to: %s\n", outputFile)
	fmt.Printf("📈 Processed %d input findings into %d final findings\n", inputCount, len(normalized))

	// Show summary
	showSummary(normalized)
}

// extractTrivyVulnerabilities extracts all vulnerabilities from trivy Results format
func extractTrivyVulnerabilities(results []interface{}) []interface{} {
	var allVulnerabilities []interface{}

	for _, result := range results {
		if resultMap, ok := result.(map[string]interface{}); ok {
			if vulnerabilities, exists := resultMap["Vulnerabilities"]; exists {
				if vulnArray, ok := vulnerabilities.([]interface{}); ok {
					allVulnerabilities = append(allVulnerabilities, vulnArray...)
				}
			}
		}
	}

	return allVulnerabilities
}

// extractNjsscanFindings flattens njsscan nested results
func extractNjsscanFindings(nodejs map[string]interface{}) []interface{} {
	var allFindings []interface{}

	for ruleID, ruleData := range nodejs {
		rMap, ok := ruleData.(map[string]interface{})
		if !ok {
			continue
		}

		metadata, _ := rMap["metadata"].(map[string]interface{})
		files, _ := rMap["files"].([]interface{})

		if len(files) == 0 {
			// Global finding
			finding := map[string]interface{}{
				"RuleID":  ruleID,
				"_tool":   "njsscan",
				"File":    "global",
			}
			for k, v := range metadata {
				finding[k] = v
			}
			allFindings = append(allFindings, finding)
			continue
		}

		for _, f := range files {
			fMap, ok := f.(map[string]interface{})
			if !ok {
				continue
			}

			finding := make(map[string]interface{})
			// Copy file details
			for k, v := range fMap {
				finding[k] = v
			}
			// Copy metadata
			for k, v := range metadata {
				finding[k] = v
			}
			// Add rule ID and tool
			finding["RuleID"] = ruleID
			finding["_tool"] = "njsscan"
			
			// Map file_path to File and match_lines to Line if needed
			if path, ok := fMap["file_path"].(string); ok {
				finding["File"] = path
			}
			if lines, ok := fMap["match_lines"].([]interface{}); ok && len(lines) > 0 {
				finding["Line"] = lines[0]
			}

			allFindings = append(allFindings, finding)
		}
	}

	return allFindings
}

// extractOSVFindings flattens OSV hierarchical results
func extractOSVFindings(results []interface{}) []interface{} {
	var allFindings []interface{}

	for _, res := range results {
		resMap, ok := res.(map[string]interface{})
		if !ok {
			continue
		}

		source, _ := resMap["source"].(map[string]interface{})
		path, _ := source["path"].(string)
		packages, _ := resMap["packages"].([]interface{})

		for _, pkg := range packages {
			pkgMap, ok := pkg.(map[string]interface{})
			if !ok {
				continue
			}

			packageInfo, _ := pkgMap["package"].(map[string]interface{})
			vulnerabilities, _ := pkgMap["vulnerabilities"].([]interface{})

			for _, vuln := range vulnerabilities {
				vulnMap, ok := vuln.(map[string]interface{})
				if !ok {
					continue
				}

				finding := make(map[string]interface{})
				// Copy vulnerability details
				for k, v := range vulnMap {
					finding[k] = v
				}

				// Add package info and source path
				finding["_tool"] = "osv"
				finding["File"] = path
				finding["RuleID"] = vulnMap["id"]
				finding["package_name"] = packageInfo["name"]
				finding["package_version"] = packageInfo["version"]
				finding["ecosystem"] = packageInfo["ecosystem"]
				finding["Confidence"] = "Certain"

				// Promote severity from database_specific if present
				if dbSpec, ok := vulnMap["database_specific"].(map[string]interface{}); ok {
					if sev, ok := dbSpec["severity"].(string); ok {
						finding["Severity"] = sev
					}
				}
				allFindings = append(allFindings, finding)
			}
		}
	}

	return allFindings
}

func loadJSONFile(filename string) ([]interface{}, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Try to decode as object first (bandit format)
	var objData map[string]interface{}
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&objData); err != nil {
		// If not an object, try as array
		file.Seek(0, 0)
		var arrData []interface{}
		if err2 := decoder.Decode(&arrData); err2 != nil {
			return nil, fmt.Errorf("failed to decode JSON: %v", err)
		}
		return arrData, nil
	}

	// Extract results array from object (try different field names)
	resultsFields := []string{"results", "Results", "findings", "Findings", "nodejs"}
	for _, field := range resultsFields {
		if results, ok := objData[field]; ok {
			// Njsscan format: "nodejs": { "rule_id": { ... } }
			if field == "nodejs" {
				if nodejsMap, ok := results.(map[string]interface{}); ok {
					return extractNjsscanFindings(nodejsMap), nil
				}
			}

			if resultsArray, ok := results.([]interface{}); ok {
				// Check for OSV format (nested source/packages)
				if field == "results" && len(resultsArray) > 0 {
					if first, ok := resultsArray[0].(map[string]interface{}); ok {
						if _, hasSource := first["source"]; hasSource {
							return extractOSVFindings(resultsArray), nil
						}
					}
				}

				// Check if this is trivy format with nested vulnerabilities
				if field == "Results" {
					vulns := extractTrivyVulnerabilities(resultsArray)
					return vulns, nil
				}
				return resultsArray, nil
			}
		}
	}

	return nil, fmt.Errorf("no results array found in JSON")
}

func saveJSONFile(filename string, data interface{}) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

func showSummary(findings []findings_processor.NormalizedFinding) {
	fmt.Println("\n📋 SUMMARY:")

	// Count by severity
	severityCount := make(map[findings_processor.SeverityLevel]int)
	categoryCount := make(map[findings_processor.FindingCategory]int)
	toolCount := make(map[string]int)

	for _, f := range findings {
		severityCount[f.Severity]++
		categoryCount[f.Category]++
		toolCount[f.Tool]++
	}

	fmt.Println("🔥 By Severity:")
	for sev, count := range severityCount {
		fmt.Printf("  %s: %d\n", sev, count)
	}

	fmt.Println("📂 By Category:")
	for cat, count := range categoryCount {
		fmt.Printf("  %s: %d\n", cat, count)
	}

	fmt.Println("🔧 By Tool:")
	for tool, count := range toolCount {
		fmt.Printf("  %s: %d\n", tool, count)
	}
}
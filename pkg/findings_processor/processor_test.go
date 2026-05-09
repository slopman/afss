package findings_processor

import (
	"encoding/json"
	"os"
	"testing"
)

func TestFindingsProcessor(t *testing.T) {
	// Load test data
	testData, err := loadTestFindings()
	if err != nil {
		t.Fatalf("Failed to load test data: %v", err)
	}

	// Create processor with default config
	config := DefaultConfig()
	processor := NewFindingsProcessor(config)

	// Process findings
	normalized, _, err := processor.Process(testData)
	if err != nil {
		t.Fatalf("Processing failed: %v", err)
	}

	// Basic validation
	if len(normalized) == 0 {
		t.Error("Expected some normalized findings")
	}

	// Check that findings are properly normalized
	for i, finding := range normalized {
		if finding.ID == "" {
			t.Errorf("Finding %d has empty ID", i)
		}
		if finding.Tool == "" {
			t.Errorf("Finding %d has empty tool", i)
		}
		if finding.Severity == "" {
			t.Errorf("Finding %d has empty severity", i)
		}
		if finding.Confidence == "" {
			t.Errorf("Finding %d has empty confidence", i)
		}
		if finding.Category == "" {
			t.Errorf("Finding %d has empty category", i)
		}
		if finding.Timestamp.IsZero() {
			t.Errorf("Finding %d has zero timestamp", i)
		}
	}
}

func TestNormalizer(t *testing.T) {
	normalizer := NewDefaultNormalizer()

	// Test raw finding
	rawFinding := map[string]interface{}{
		"Title":       "Test vulnerability",
		"Description": "This is a test",
		"File":        "test.go",
		"Line":         42,
		"Severity":    "HIGH",
		"confidence":  "MEDIUM",
		"_tool":       "test_tool",
		"RuleID":      "TEST-001",
		"code":        "func test() { /* comment */ fmt.Println(\"hello\") }",
		"cwe":         []interface{}{"CWE-123"},
	}

	rawFindings := []interface{}{rawFinding}

	normalized, err := normalizer.Normalize(rawFindings)
	if err != nil {
		t.Fatalf("Normalization failed: %v", err)
	}

	if len(normalized) != 1 {
		t.Fatalf("Expected 1 normalized finding, got %d", len(normalized))
	}

	finding := normalized[0]

	// Check normalized fields
	if finding.Title != "Test vulnerability" {
		t.Errorf("Expected title 'Test vulnerability', got '%s'", finding.Title)
	}
	if finding.Severity != High {
		t.Errorf("Expected severity High, got %s", finding.Severity)
	}
	if finding.Confidence != Likely {
		t.Errorf("Expected confidence Likely, got %s", finding.Confidence)
	}
	if finding.Category != CodeFinding {
		t.Errorf("Expected category CodeFinding, got %s", finding.Category)
	}
	if len(finding.CWE) != 1 || finding.CWE[0] != "CWE-123" {
		t.Errorf("Expected CWE ['CWE-123'], got %v", finding.CWE)
	}
}

func TestDeduplicator(t *testing.T) {
	config := DefaultConfig()
	deduplicator := NewAggressiveDeduplicator(config)

	// Create duplicate findings
	finding1 := NormalizedFinding{
		ID:          "1",
		Title:       "Test vuln",
		File:        "test.go",
		Line:         10,
		CodeSnippet: "func test() { fmt.Println(\"hello\") }",
		CWE:         []string{"CWE-123"},
		Tool:        "tool1",
		Severity:    High,
		Confidence:  Certain,
	}

	finding2 := NormalizedFinding{
		ID:          "2",
		Title:       "Test vuln",
		File:        "test.go",
		Line:         10,
		CodeSnippet: "func test() { fmt.Println(\"hello\") }", // Same code
		CWE:         []string{"CWE-123"},
		Tool:        "tool2",
		Severity:    Medium, // Different severity
		Confidence:  Likely,
	}

	findings := []NormalizedFinding{finding1, finding2}

	deduplicated, err := deduplicator.Deduplicate(findings)
	if err != nil {
		t.Fatalf("Deduplication failed: %v", err)
	}

	// Should be deduplicated to 1 finding
	if len(deduplicated) != 1 {
		t.Errorf("Expected 1 deduplicated finding, got %d", len(deduplicated))
	}

	// Check that the merged finding has metadata
	merged := deduplicated[0]
	if duplicateCount, exists := merged.RawData["_duplicate_count"]; !exists || duplicateCount != 2 {
		t.Errorf("Expected duplicate_count=2, got %v", duplicateCount)
	}
}

func loadTestFindings() ([]interface{}, error) {
	// Try to load from our processed test data
	file, err := os.Open("../../../test/test_results/final_unique_findings.json")
	if err != nil {
		// If test data not available, create mock data
		return createMockFindings(), nil
	}
	defer file.Close()

	var findings []interface{}
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&findings)
	return findings, err
}

func createMockFindings() []interface{} {
	return []interface{}{
		map[string]interface{}{
			"Title":       "SQL Injection",
			"Description": "Potential SQL injection vulnerability",
			"File":        "app.py",
			"Line":         25,
			"Severity":    "HIGH",
			"confidence":  "MEDIUM",
			"_tool":       "bandit",
			"RuleID":      "B608",
			"code":        "cursor.execute(\"SELECT * FROM users WHERE id = \" + user_id)",
			"cwe":         []interface{}{"CWE-89"},
		},
		map[string]interface{}{
			"Title":       "Hardcoded password",
			"Description": "Hardcoded password detected",
			"File":        "config.py",
			"Line":         10,
			"Severity":    "MEDIUM",
			"confidence":  "HIGH",
			"_tool":       "gitleaks",
			"RuleID":      "hardcoded-password",
			"Match":       "password = 'admin123'",
			"cwe":         []interface{}{"CWE-798"},
		},
	}
}
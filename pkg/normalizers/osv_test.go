package normalizers

import (
	"os"
	"testing"

	"github.com/security-scanner/afss-orchestrator/pkg/findings_processor"
)

func TestOSVNormalizer_CanHandle(t *testing.T) {
	n := NewOSVNormalizer()

	tests := []struct {
		name     string
		rawData  string
		expected bool
	}{
		{
			name:     "Valid OSV JSON",
			rawData:  `{ "results": [ { "source": { "path": "yarn.lock", "type": "lockfile" } } ] }`,
			expected: true,
		},
		{
			name:     "Invalid JSON",
			rawData:  `{ "not": "osv" }`,
			expected: false,
		},
		{
			name:     "Empty Results",
			rawData:  `{ "results": [] }`,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := n.CanHandle([]byte(tt.rawData)); got != tt.expected {
				t.Errorf("OSVNormalizer.CanHandle() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestOSVNormalizer_Normalize(t *testing.T) {
	n := NewOSVNormalizer()

	rawData := `{
		"results": [
			{
				"source": { "path": "yarn.lock", "type": "lockfile" },
				"packages": [
					{
						"package": { "name": "pkg1", "version": "1.0.0", "ecosystem": "npm" },
						"vulnerabilities": [
							{
								"id": "GHSA-1",
								"summary": "Vuln 1",
								"details": "Details 1",
								"database_specific": { "severity": "HIGH", "cwe_ids": ["CWE-1"] }
							},
							{
								"id": "GHSA-2",
								"summary": "Vuln 2",
								"database_specific": { "severity": "LOW" }
							}
						]
					}
				]
			}
		]
	}`

	findings, err := n.Normalize([]byte(rawData))
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("Expected 2 findings, got %d", len(findings))
	}

	if findings[0].RuleID != "GHSA-1" || findings[0].Severity != findings_processor.High {
		t.Errorf("Findings[0] mismatch: %+v", findings[0])
	}
	if findings[1].RuleID != "GHSA-2" || findings[1].Severity != findings_processor.Low {
		t.Errorf("Findings[1] mismatch: %+v", findings[1])
	}
	if findings[0].File != "yarn.lock" {
		t.Errorf("File path mismatch: %v", findings[0].File)
	}
}

func TestOSVNormalizer_RealFile(t *testing.T) {
	n := NewOSVNormalizer()
	const filePath = "../../test/test_results/wallet_osv_results.json"

	rawData, err := os.ReadFile(filePath)
	if err != nil {
		t.Skipf("Skipping real file test: %v", err)
		return
	}

	findings, err := n.Normalize(rawData)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("Expected some findings, got 0")
	}

	t.Logf("Successfully normalized %d findings from %s", len(findings), filePath)
	
	// Check one from the real file
	found := false
	for _, f := range findings {
		if f.RuleID == "GHSA-xffm-g5w8-qvg7" {
			found = true
			if f.Severity != findings_processor.Low {
				t.Errorf("Expected severity LOW for GHSA-xffm-g5w8-qvg7, got %v", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("Did not find GHSA-xffm-g5w8-qvg7 in real data")
	}
}

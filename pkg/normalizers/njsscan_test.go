package normalizers

import (
	"os"
	"testing"

	"github.com/security-scanner/afss-orchestrator/pkg/findings_processor"
)

func TestNjsscanNormalizer_CanHandle(t *testing.T) {
	n := NewNjsscanNormalizer()

	tests := []struct {
		name     string
		rawData  string
		expected bool
	}{
		{
			name:     "Valid Njsscan JSON",
			rawData:  `{ "njsscan_version": "0.4.3", "nodejs": {} }`,
			expected: true,
		},
		{
			name:     "Another Valid Njsscan JSON",
			rawData:  `{ "nodejs": { "rule": {} } }`,
			expected: true,
		},
		{
			name:     "Invalid JSON",
			rawData:  `{ "not": "njsscan" }`,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := n.CanHandle([]byte(tt.rawData)); got != tt.expected {
				t.Errorf("NjsscanNormalizer.CanHandle() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestNjsscanNormalizer_Normalize(t *testing.T) {
	n := NewNjsscanNormalizer()

	rawData := `{
		"nodejs": {
			"rule1": {
				"metadata": {
					"severity": "ERROR",
					"description": "Critical issue",
					"cwe": "CWE-123: Test CWE"
				},
				"files": [
					{
						"file_path": "server.js",
						"match_lines": [10, 10]
					}
				]
			},
			"rule2": {
				"metadata": {
					"severity": "WARNING",
					"description": "Warning issue"
				}
			}
		}
	}`

	findings, err := n.Normalize([]byte(rawData))
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("Expected 2 findings, got %d", len(findings))
	}

	// findings are from a map, so order is not guaranteed. 
	// find rule1 and rule2
	var f1, f2 findings_processor.NormalizedFinding
	for _, f := range findings {
		if f.RuleID == "rule1" {
			f1 = f
		} else if f.RuleID == "rule2" {
			f2 = f
		}
	}

	if f1.Title != "Critical issue" {
		t.Errorf("f1.Title = %v, want %v", f1.Title, "Critical issue")
	}
	if f1.Severity != findings_processor.High {
		t.Errorf("f1.Severity = %v, want %v", f1.Severity, findings_processor.High)
	}
	if f1.File != "server.js" {
		t.Errorf("f1.File = %v, want %v", f1.File, "server.js")
	}
	if len(f1.CWE) != 1 || f1.CWE[0] != "CWE-123" {
		t.Errorf("f1.CWE = %v, want %v", f1.CWE, []string{"CWE-123"})
	}

	if f2.File != "global" {
		t.Errorf("f2.File = %v, want %v", f2.File, "global")
	}
	if f2.Severity != findings_processor.Medium {
		t.Errorf("f2.Severity = %v, want %v", f2.Severity, findings_processor.Medium)
	}
}

func TestNjsscanNormalizer_RealFile(t *testing.T) {
	n := NewNjsscanNormalizer()
	const filePath = "../../test/test_results/wallet_nodejsscan_results.json"

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
}

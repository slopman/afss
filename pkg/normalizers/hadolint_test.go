package normalizers

import (
	"testing"

	"github.com/security-scanner/afss-orchestrator/pkg/findings_processor"
)

func TestHadolintNormalizer_CanHandle(t *testing.T) {
	n := NewHadolintNormalizer()

	tests := []struct {
		name     string
		rawData  string
		expected bool
	}{
		{
			name: "Valid Hadolint JSON",
			rawData: `[
				{
					"line": 1,
					"code": "DL3006",
					"message": "Always tag the version of an image explicitly",
					"column": 1,
					"file": "Dockerfile",
					"level": "warning"
				}
			]`,
			expected: true,
		},
		{
			name: "Valid Hadolint JSON (SH rule)",
			rawData: `[
				{
					"line": 5,
					"code": "SH2034",
					"message": "foo appears unused. Verify it or export it.",
					"column": 1,
					"file": "Dockerfile",
					"level": "info"
				}
			]`,
			expected: true,
		},
		{
			name:     "Invalid JSON",
			rawData:  `{ "not": "an array" }`,
			expected: false,
		},
		{
			name:     "Empty Array",
			rawData:  `[]`,
			expected: false,
		},
		{
			name: "Other JSON",
			rawData: `[
				{
					"foo": "bar"
				}
			]`,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := n.CanHandle([]byte(tt.rawData)); got != tt.expected {
				t.Errorf("HadolintNormalizer.CanHandle() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestHadolintNormalizer_Normalize(t *testing.T) {
	n := NewHadolintNormalizer()

	rawData := `[
		{
			"line": 1,
			"code": "DL3006",
			"message": "Always tag the version of an image explicitly",
			"column": 1,
			"file": "Dockerfile",
			"level": "warning"
		},
		{
			"line": 10,
			"code": "DL3008",
			"message": "Pin versions in apt get install",
			"column": 1,
			"file": "Dockerfile",
			"level": "error"
		}
	]`

	findings, err := n.Normalize([]byte(rawData))
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("Expected 2 findings, got %d", len(findings))
	}

	// Check first finding
	f1 := findings[0]
	if f1.Title != "Always tag the version of an image explicitly" {
		t.Errorf("f1.Title = %v, want %v", f1.Title, "Always tag the version of an image explicitly")
	}
	if f1.Severity != findings_processor.Medium {
		t.Errorf("f1.Severity = %v, want %v", f1.Severity, findings_processor.Medium)
	}
	if f1.Line != 1 {
		t.Errorf("f1.Line = %v, want %v", f1.Line, 1)
	}
	if f1.RuleID != "DL3006" {
		t.Errorf("f1.RuleID = %v, want %v", f1.RuleID, "DL3006")
	}

	// Check second finding
	f2 := findings[1]
	if f2.Severity != findings_processor.High {
		t.Errorf("f2.Severity = %v, want %v", f2.Severity, findings_processor.High)
	}
	if f2.Line != 10 {
		t.Errorf("f2.Line = %v, want %v", f2.Line, 10)
	}
}


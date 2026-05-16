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
			name:     "Empty JSON array then parse error line",
			rawData:  "[]\nhadolint: /scan/Dockerfile: withBinaryFile: cannot read",
			expected: true,
		},
		{
			name:     "TTY-style line",
			rawData:  "Dockerfile:5 DL3006 Always tag the version of an image explicitly",
			expected: true,
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

func TestHadolintNormalizer_Normalize_ParseErrorPlaintext(t *testing.T) {
	n := NewHadolintNormalizer()
	raw := "hadolint: /scan/Dockerfile: withBinaryFile: cannot read file"
	findings, err := n.Normalize([]byte(raw))
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if findings[0].RuleID != "HADOLINT_PARSE" {
		t.Errorf("RuleID = %q, want HADOLINT_PARSE", findings[0].RuleID)
	}
	if findings[0].File != "/scan/Dockerfile" {
		t.Errorf("File = %q", findings[0].File)
	}
}

func TestHadolintNormalizer_Normalize_EmptyJSONArrayPlusParseError(t *testing.T) {
	n := NewHadolintNormalizer()
	raw := "[]\nhadolint: /scan/Dockerfile: withBinaryFile: cannot read file"
	findings, err := n.Normalize([]byte(raw))
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if findings[0].RuleID != "HADOLINT_PARSE" {
		t.Errorf("RuleID = %q", findings[0].RuleID)
	}
}

func TestHadolintNormalizer_Normalize_JSONFindingsPlusParseErrorTail(t *testing.T) {
	n := NewHadolintNormalizer()
	raw := `[
		{
			"line": 1,
			"code": "DL3006",
			"message": "Always tag the version of an image explicitly",
			"column": 1,
			"file": "Dockerfile",
			"level": "warning"
		}
	]
hadolint: /scan/Dockerfile: withBinaryFile: cannot read file`
	findings, err := n.Normalize([]byte(raw))
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("want 2 findings, got %d", len(findings))
	}
	if findings[1].RuleID != "HADOLINT_PARSE" {
		t.Errorf("second finding RuleID = %q", findings[1].RuleID)
	}
}


package findings_processor

import (
	"testing"
)

func TestBasicCorrelator_SameVulnerability(t *testing.T) {
	correlator := NewBasicCorrelator()

	findings := []NormalizedFinding{
		{
			ID:   "f1",
			File: "app.go",
			Line: 10,
			CWE:  []string{"CWE-89"},
			Tool: "gosec",
		},
		{
			ID:   "f2",
			File: "app.go",
			Line: 10,
			CWE:  []string{"CWE-89"},
			Tool: "semgrep",
		},
	}

	correlations, err := correlator.Correlate(findings)
	if err != nil {
		t.Fatalf("Correlation failed: %v", err)
	}

	found := false
	for _, c := range correlations {
		if c.Type == SameVulnerability {
			found = true
			if len(c.Findings) != 2 {
				t.Errorf("Expected 2 findings in correlation, got %d", len(c.Findings))
			}
		}
	}

	if !found {
		t.Error("SameVulnerability correlation not found")
	}
}

func TestBasicCorrelator_SameFile(t *testing.T) {
	correlator := NewBasicCorrelator()

	findings := []NormalizedFinding{
		{
			ID:   "f1",
			File: "app.go",
			Line: 10,
			Tool: "gosec",
		},
		{
			ID:   "f2",
			File: "app.go",
			Line: 20,
			Tool: "semgrep",
		},
	}

	correlations, err := correlator.Correlate(findings)
	if err != nil {
		t.Fatalf("Correlation failed: %v", err)
	}

	found := false
	for _, c := range correlations {
		if c.Type == SameFile {
			found = true
			if len(c.Findings) != 2 {
				t.Errorf("Expected 2 findings in same file correlation, got %d", len(c.Findings))
			}
		}
	}

	if !found {
		t.Error("SameFile correlation not found")
	}
}

func TestBasicCorrelator_SamePackage(t *testing.T) {
	correlator := NewBasicCorrelator()

	findings := []NormalizedFinding{
		{
			ID:   "f1",
			File: "pkg/auth/login.go",
			Tool: "gosec",
		},
		{
			ID:   "f2",
			File: "pkg/auth/logout.go",
			Tool: "semgrep",
		},
	}

	correlations, err := correlator.Correlate(findings)
	if err != nil {
		t.Fatalf("Correlation failed: %v", err)
	}

	found := false
	for _, c := range correlations {
		if c.Type == SamePackage {
			found = true
			if len(c.Findings) != 2 {
				t.Errorf("Expected 2 findings in same package correlation, got %d", len(c.Findings))
			}
		}
	}

	if !found {
		t.Error("SamePackage correlation not found")
	}
}

func TestBasicCorrelator_DependencyChain(t *testing.T) {
	correlator := NewBasicCorrelator()

	findings := []NormalizedFinding{
		{
			ID:       "v1",
			Category: VulnFinding,
			RawData: map[string]interface{}{
				"PackageName": "lodash",
			},
			Tool: "trivy",
		},
		{
			ID:       "v2",
			Category: VulnFinding,
			RawData: map[string]interface{}{
				"package_name": "lodash",
			},
			Tool: "osv",
		},
	}

	correlations, err := correlator.Correlate(findings)
	if err != nil {
		t.Fatalf("Correlation failed: %v", err)
	}

	found := false
	for _, c := range correlations {
		if c.Type == DependencyChain {
			found = true
			if len(c.Findings) != 2 {
				t.Errorf("Expected 2 findings in dependency chain correlation, got %d", len(c.Findings))
			}
		}
	}

	if !found {
		t.Error("DependencyChain correlation not found")
	}
}

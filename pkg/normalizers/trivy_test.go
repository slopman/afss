package normalizers

import (
	"testing"

	"github.com/security-scanner/afss-orchestrator/pkg/findings_processor"
)

func TestTrivyNormalizer_SecretsOnly(t *testing.T) {
	n := NewTrivyNormalizer()
	raw := `{"SchemaVersion":2,"ArtifactName":".","Results":[{"Target":"package.json","Class":"secret","Secrets":[{"RuleID":"generic-api-key","Severity":"HIGH","Title":"API","StartLine":3}]}]}`
	out, err := n.Normalize([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1 finding, got %d", len(out))
	}
	if out[0].Category != findings_processor.SecretFinding {
		t.Fatalf("category %q", out[0].Category)
	}
}

func TestTrivyNormalizer_NullResults(t *testing.T) {
	n := NewTrivyNormalizer()
	raw := `{"SchemaVersion":2,"ArtifactName":".","Results":null}`
	out, err := n.Normalize([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Fatalf("want 0, got %d", len(out))
	}
}

// Trivy 0.70+ may omit "Results" when there are zero findings (repository metadata only).
func TestTrivyNormalizer_OmittedResultsEnvelope(t *testing.T) {
	n := NewTrivyNormalizer()
	raw := `{"SchemaVersion":2,"ArtifactName":"/scan","ArtifactType":"repository","Metadata":{"RepoURL":"https://github.com/example/example.git","Branch":"main"}}`
	if !n.CanHandle([]byte(raw)) {
		t.Fatal("CanHandle: expected true for Trivy envelope without Results")
	}
	out, err := n.Normalize([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Fatalf("want 0 findings, got %d", len(out))
	}
}

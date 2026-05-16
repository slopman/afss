package normalizers

import "testing"

func TestGitleaksNormalizer_TrailingNoiseAfterArray(t *testing.T) {
	n := NewGitleaksNormalizer()
	raw := `[{"RuleID":"test","Secret":"x","File":"a.go","StartLine":1}]message`
	out, err := n.Normalize([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1 finding, got %d", len(out))
	}
}

func TestGitleaksNormalizer_SingleObject(t *testing.T) {
	n := NewGitleaksNormalizer()
	raw := `{"RuleID":"r","Secret":"s","File":"b.go","StartLine":2}`
	out, err := n.Normalize([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].RuleID != "r" {
		t.Fatalf("got %+v", out)
	}
}

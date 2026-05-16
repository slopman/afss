package util

import "testing"

func TestFirstJSONValue(t *testing.T) {
	const noisy = `some log line
{"a":1}{"b":2}`
	got := FirstJSONValue(noisy)
	if got != `{"a":1}` {
		t.Fatalf("got %q want first object only", got)
	}
	if FirstJSONValue("no json") != "" {
		t.Fatal("expected empty")
	}
}

func TestFirstJSONObjectWithKey(t *testing.T) {
	const noisy = `level=info {"msg":"x"}
{"SchemaVersion":2,"Results":[]}`
	got := FirstJSONObjectWithKey(noisy, "Results")
	if got == "" {
		t.Fatal("expected non-empty")
	}
	if got != `{"SchemaVersion":2,"Results":[]}` {
		t.Fatalf("got %q", got)
	}
}

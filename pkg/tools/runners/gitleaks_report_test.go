package runners

import (
	"testing"

	"github.com/security-scanner/afss-orchestrator/pkg/models"
)

func TestGitleaksReportPath_Default(t *testing.T) {
	cfg := &models.ToolConfig{CLI: map[string]interface{}{}}
	if p := GitleaksReportPath(cfg); p != DefaultGitleaksReportPath {
		t.Fatalf("got %q", p)
	}
}

func TestGitleaksReportPathForRead_Relative(t *testing.T) {
	cfg := &models.ToolConfig{CLI: map[string]interface{}{"report_path": "out/gl.json"}}
	if p := GitleaksReportPathForRead(cfg, "/repo"); p != "/repo/out/gl.json" {
		t.Fatalf("got %q", p)
	}
}

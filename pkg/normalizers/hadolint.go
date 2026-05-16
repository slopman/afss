package normalizers

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/security-scanner/afss-orchestrator/pkg/findings_processor"
)

// HadolintNormalizer handles Hadolint output
type HadolintNormalizer struct{}

// NewHadolintNormalizer creates a new Hadolint normalizer
func NewHadolintNormalizer() *HadolintNormalizer {
	return &HadolintNormalizer{}
}

// ToolName returns the tool name
func (n *HadolintNormalizer) ToolName() string {
	return "hadolint"
}

// CanHandle checks if this normalizer can handle the given data
func (n *HadolintNormalizer) CanHandle(rawData []byte) bool {
	s := strings.TrimSpace(string(rawData))
	if s == "" {
		return false
	}
	if n.looksLikeHadolintPlaintext(s) {
		return true
	}
	if results, _, ok := decodeFirstHadolintJSONArray(s); ok {
		if len(results) == 0 {
			return false
		}
		first := results[0]
		code, hasCode := first["code"].(string)
		_, hasLevel := first["level"].(string)
		_, hasMessage := first["message"].(string)
		if hasCode && hasLevel && hasMessage {
			if strings.HasPrefix(code, "DL") || strings.HasPrefix(code, "SH") {
				return true
			}
		}
		return false
	}
	return false
}

// looksLikeHadolintPlaintext detects tty lines or hadolint parse-error text.
func (n *HadolintNormalizer) looksLikeHadolintPlaintext(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if strings.Contains(strings.ToLower(s), "hadolint:") {
		return true
	}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if n.parseHadolintTTYLine(line) != nil {
			return true
		}
	}
	return false
}

// decodeFirstHadolintJSONArray finds the first top-level JSON array in s, decodes it,
// and returns any trailing non-JSON text (e.g. stderr lines after "[]").
func decodeFirstHadolintJSONArray(s string) (results []map[string]interface{}, tail string, ok bool) {
	s = strings.TrimSpace(s)
	start := strings.IndexByte(s, '[')
	if start < 0 {
		return nil, "", false
	}
	dec := json.NewDecoder(strings.NewReader(s[start:]))
	var raw json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return nil, "", false
	}
	if err := json.Unmarshal(raw, &results); err != nil {
		return nil, "", false
	}
	end := start + int(dec.InputOffset())
	tail = strings.TrimSpace(s[end:])
	return results, tail, true
}

// Normalize converts Hadolint output to normalized findings
func (n *HadolintNormalizer) Normalize(rawData []byte) ([]findings_processor.NormalizedFinding, error) {
	s := strings.TrimSpace(string(rawData))
	if results, tail, ok := decodeFirstHadolintJSONArray(s); ok {
		var out []findings_processor.NormalizedFinding
		if len(results) > 0 {
			arr, err := n.normalizeJSONArray(results)
			if err != nil {
				return nil, err
			}
			out = append(out, arr...)
		}
		if tail != "" {
			ext, err := n.normalizePlaintext(tail)
			if err != nil {
				if len(out) > 0 {
					return out, nil
				}
				return nil, err
			}
			out = append(out, ext...)
		}
		if len(out) == 0 {
			return nil, nil
		}
		return out, nil
	}
	return n.normalizePlaintext(s)
}

func (n *HadolintNormalizer) normalizeJSONArray(results []map[string]interface{}) ([]findings_processor.NormalizedFinding, error) {
	var normalized []findings_processor.NormalizedFinding

	for _, result := range results {
		finding := findings_processor.NormalizedFinding{
			RawData: result,
			Tool:    "hadolint",
		}

		// Extract fields using helpers
		finding.Title = n.extractString(result, []string{"message"}, "No message")
		finding.Description = finding.Title
		finding.File = n.extractString(result, []string{"file"}, "Dockerfile")
		finding.Line = n.extractInt(result, []string{"line"}, 0)
		finding.RuleID = n.extractString(result, []string{"code"}, "unknown")

		// Hadolint categories are configuration-related
		finding.Category = findings_processor.ConfigFinding

		// Default confidence for linter rules
		finding.Confidence = findings_processor.Certain

		// Map severity
		severityStr := n.extractString(result, []string{"level"}, "info")
		finding.Severity = n.normalizeSeverity(severityStr)

		// Generate ID
		finding.ID = fmt.Sprintf("hadolint_%s_%s_%d", finding.File, finding.RuleID, finding.Line)

		normalized = append(normalized, finding)
	}

	return normalized, nil
}

func (n *HadolintNormalizer) normalizePlaintext(s string) ([]findings_processor.NormalizedFinding, error) {
	var normalized []findings_processor.NormalizedFinding
	seen := make(map[string]struct{})
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if f := n.parseHadolintTTYLine(line); f != nil {
			if _, ok := seen[f.ID]; ok {
				continue
			}
			seen[f.ID] = struct{}{}
			normalized = append(normalized, *f)
			continue
		}
		if f := n.parseHadolintErrorLine(line); f != nil {
			if _, ok := seen[f.ID]; ok {
				continue
			}
			seen[f.ID] = struct{}{}
			normalized = append(normalized, *f)
		}
	}
	if len(normalized) == 0 {
		return nil, fmt.Errorf("hadolint: unrecognized plain text output")
	}
	return normalized, nil
}

// parseHadolintTTYLine parses lines like "Dockerfile:5 DL3006 message here".
func (n *HadolintNormalizer) parseHadolintTTYLine(line string) *findings_processor.NormalizedFinding {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 3 {
		return nil
	}
	location, code, message := parts[0], parts[1], parts[2]
	if !strings.HasPrefix(code, "DL") && !strings.HasPrefix(code, "SH") {
		return nil
	}
	if !strings.Contains(location, ":") {
		return nil
	}
	locParts := strings.Split(location, ":")
	if len(locParts) < 2 {
		return nil
	}
	file := strings.Join(locParts[:len(locParts)-1], ":")
	lineNumStr := locParts[len(locParts)-1]
	var lineNum int
	_, _ = fmt.Sscanf(lineNumStr, "%d", &lineNum)

	raw := map[string]interface{}{
		"file": file, "line": float64(lineNum), "code": code, "message": message, "level": "warning",
	}
	f := findings_processor.NormalizedFinding{
		RawData:     raw,
		Title:       message,
		Description: message,
		File:        file,
		Line:        lineNum,
		RuleID:      code,
		Tool:        "hadolint",
		Category:    findings_processor.ConfigFinding,
		Confidence:  findings_processor.Certain,
		Severity:    findings_processor.Medium,
		ID:          fmt.Sprintf("hadolint_%s_%s_%d", file, code, lineNum),
	}
	return &f
}

// parseHadolintErrorLine parses messages like "hadolint: /scan/Dockerfile: withBinaryFile: ...".
func (n *HadolintNormalizer) parseHadolintErrorLine(line string) *findings_processor.NormalizedFinding {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	rest := line
	if len(line) >= 9 && strings.EqualFold(line[:9], "hadolint:") {
		rest = strings.TrimSpace(line[9:])
	}
	sep := strings.Index(rest, ": ")
	if sep <= 0 || sep >= len(rest)-2 {
		return nil
	}
	file := strings.TrimSpace(rest[:sep])
	msg := strings.TrimSpace(rest[sep+2:])
	if file == "" || msg == "" {
		return nil
	}
	// Avoid treating tty lines as errors (those use a rule code in the second token).
	if strings.HasPrefix(strings.TrimSpace(msg), "DL") || strings.HasPrefix(strings.TrimSpace(msg), "SH") {
		return nil
	}
	raw := map[string]interface{}{"file": file, "message": msg, "code": "HADOLINT_PARSE"}
	f := findings_processor.NormalizedFinding{
		RawData:     raw,
		Title:       msg,
		Description: msg,
		File:        file,
		Line:        0,
		RuleID:      "HADOLINT_PARSE",
		Tool:        "hadolint",
		Category:    findings_processor.ConfigFinding,
		Confidence:  findings_processor.Certain,
		Severity:    findings_processor.Medium,
		ID:          fmt.Sprintf("hadolint_parse_%s", file),
	}
	return &f
}

// normalizeSeverity converts Hadolint level to standard levels
func (n *HadolintNormalizer) normalizeSeverity(level string) findings_processor.SeverityLevel {
	switch strings.ToLower(level) {
	case "error":
		return findings_processor.High
	case "warning":
		return findings_processor.Medium
	case "info":
		return findings_processor.Low
	case "style":
		return findings_processor.Info
	default:
		return findings_processor.Info
	}
}

// Helper methods for extracting values
func (n *HadolintNormalizer) extractString(data map[string]interface{}, fields []string, defaultValue string) string {
	for _, field := range fields {
		if val, exists := data[field]; exists {
			if strVal, ok := val.(string); ok && strVal != "" {
				return strVal
			}
		}
	}
	return defaultValue
}

func (n *HadolintNormalizer) extractInt(data map[string]interface{}, fields []string, defaultValue int) int {
	for _, field := range fields {
		if val, exists := data[field]; exists {
			if intVal, ok := val.(float64); ok {
				return int(intVal)
			}
			if intVal, ok := val.(int); ok {
				return intVal
			}
		}
	}
	return defaultValue
}

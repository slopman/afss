package util

import (
	"encoding/json"
	"strings"
)

// FirstJSONObjectWithKey scans s from the first '{' or '[' and decodes successive
// JSON values until it finds a top-level JSON object containing key (case-insensitive).
// Use when stdout may contain log lines or smaller JSON objects before the main report.
func FirstJSONObjectWithKey(s string, key string) string {
	s = strings.TrimSpace(s)
	start := strings.IndexAny(s, "{[")
	if start < 0 {
		return ""
	}
	dec := json.NewDecoder(strings.NewReader(s[start:]))
	for {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return ""
		}
		var probe map[string]interface{}
		if err := json.Unmarshal(raw, &probe); err != nil {
			continue
		}
		for k := range probe {
			if strings.EqualFold(k, key) {
				return string(raw)
			}
		}
	}
}

// FirstJSONValue returns the first complete JSON object or array in s, skipping
// leading non-JSON noise. Use when stdout may concatenate logs after valid JSON.
func FirstJSONValue(s string) string {
	s = strings.TrimSpace(s)
	start := strings.IndexAny(s, "{[")
	if start < 0 {
		return ""
	}
	dec := json.NewDecoder(strings.NewReader(s[start:]))
	dec.UseNumber()
	var raw json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return ""
	}
	return string(raw)
}

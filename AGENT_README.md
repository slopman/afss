# 🤖 Guide for AI Researchers / Agents

Welcome, Researcher. This project is now **Docker-First**. Use this guide to run scans efficiently and save your context window (tokens).

## 🚀 Execution Strategy: Use Docker

To avoid dependency issues (like wrong TruffleHog version or old Go), always run scans via Docker:

```bash
# Set target repo and run
export REPO_PATH=/absolute/path/to/repo
docker-compose up --build
```

**Why this is better for you:**
1. **Consistency**: You don't have to debug why a tool failed on the host. 
2. **Pre-installed Tools**: TruffleHog v3, Gosec, Semgrep, Trivy, and Govulncheck (Go 1.23) are all ready.
3. **Isolated Logs**: No side effects on the host machine.

## 📉 Token Economy: Read Actionable Findings

Security tools are noisy. **DO NOT** read the raw files in `results/raw_*.json`. 

**Steps to save 90% of tokens:**
1. **Primary Source**: Read `results/actionable_findings.json`. It is deduplicated and normalized.
2. **Correlations**: Look for the `correlations` field. If multiple tools flagged the same lines, it's a high-confidence finding.
3. **Filtering**: The Orchestrator has already filtered out "noise" (like test files or low-confidence patterns).

## 📊 Output Structure

- `results/actionable_findings.json` -> **START HERE**. Your primary input.
- `results/report.html` -> Use for visual summary (if you have browser access).
- `results/raw_[tool].json` -> Only read if you suspect the normalizer missed something.

## 🧠 Pro-Tips for Agents

1. **Path Mapping**: In Docker, the target repo is mounted to `/scan`. Findings will have paths relative to this.
2. **TruffleHog v3**: We use the Go version. If you need to tweak its config, edit `configs/tools/trufflehog.yaml`.
3. **Resource Limits**: If the host is slow, you can lower `max_parallel_scans` in `configs/orchestrator.yaml`.

---
*Optimized for Claude/GPT/Antigravity by the AFSS Team.*

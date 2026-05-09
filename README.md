# 🚀 AFSS Orchestrator

**Agent-First Security Scanner Orchestrator** - Intelligent resource-aware orchestration for security scanning tools.

## 🎯 Overview

AFSS Orchestrator is a smart orchestration layer that:
- **Docker-First Environment**: All security tools (Semgrep, Trivy, Gosec, etc.) are pre-installed in a consistent container.
- **Resource-Aware Execution**: Monitors system resources and adapts tool execution to avoid freezing.
- **Intelligent Scheduling**: Decides how many tools can run in parallel based on CPU/RAM weights.
- **Unified Reporting**: Normalizes findings from diverse tools into a single, clean JSON/HTML report.

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Agent/UI      │────│  Orchestrator    │────│ Docker Container│
│                 │    │ (Dockerized)     │    │                 │
│ - Commands      │    │ - Resource Mgmt  │    │ - Gosec (Go)    │
│ - Config Mgmt   │    │ - Scheduling     │    │ - TruffleHog v3 │
│ - Results       │    │ - Normalization  │    │ - Semgrep, etc. │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## 🚀 Quick Start (Docker)

This is the recommended way to run the orchestrator without worrying about local dependencies.

### 1. Requirements
- Docker & Docker-compose
- At least 4GB RAM recommended

### 2. Run Scan
Provide the path to your project and run:

```bash
export REPO_PATH=/path/to/your/repo
docker-compose up --build
```

### 3. View Results
- **HTML Report**: Open `results/report.html` in your browser.
- **Actionable Findings**: Check `results/actionable_findings.json` for a deduplicated list.

---

## 🛠️ Usage (Local/Development)

If you want to run it without Docker, you'll need Go 1.23+ and individual tools installed.

### Build
```bash
go build -o orchestrator ./cmd/orchestrator/*.go
```

### Run
```bash
./orchestrator scan /path/to/repo
```

## 📋 Configuration

### Orchestrator Config (`configs/orchestrator.yaml`)
Controls global limits and resource thresholds.

### Tool Configs (`configs/tools/*.yaml`)
Enable/disable specific tools and adjust their resource "weight".

---

## 🎯 Key Features

### 1. Updated Tools
- **TruffleHog Go (v3)**: Uses the modern Go rewrite for faster secret detection.
- **Go 1.23**: Fully supports latest Go features and `govulncheck`.
- **NDJSON Support**: Correctly parses newline-delimited JSON from modern tools.

### 2. Intelligent Normalization
- Automatically masks secret data in reports.
- Deduplicates identical findings across different tools.
- Ignoers non-JSON logs and "noise" from tool output.

### 3. Resource Management
- **Semaphores**: Strictly limits parallel scans to prevent system crashes.
- **Weighted Scheduling**: Heavy tools (like Semgrep) consume more "slots" than light ones.

---

## 🔧 Development

### Run Tests
```bash
go test ./...
```

### Clean Environment
```bash
rm -rf results/* debug_results/*
```

## 🤝 Contributing
Feel free to open issues or submit PRs to improve tool normalizers or scheduling logic.

## 📄 License
MIT License.
# 🚀 AFSS Orchestrator

**Agent-First Security Scanner Orchestrator** - Intelligent resource-aware orchestration for security scanning tools.

## 🎯 Overview

AFSS Orchestrator is a smart orchestration layer that:
- **Resource-Aware Execution**: Monitors system resources and adapts tool execution
- **YAML Configuration**: Clean configuration management for all security tools
- **Intelligent Scheduling**: Decides how many tools can run in parallel
- **Profiling System**: Learns resource consumption patterns of tools
- **Graceful Degradation**: Handles resource pressure and failures

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Agent/UI      │────│  Orchestrator    │────│ Security Tools  │
│                 │    │                  │    │                 │
│ - Commands      │    │ - Resource Mgmt  │    │ - Gosec         │
│ - Config Mgmt   │    │ - Scheduling     │    │ - Semgrep       │
│ - Results       │    │ - Monitoring     │    │ - TruffleHog    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌──────────────────┐
                       │   YAML Configs   │
                       │                  │
                       │ - orchestrator   │
                       │ - tools/*        │
                       │ - resource-limits│
                       └──────────────────┘
```

## 🚀 Quick Start

### 1. Build
```bash
make deps
make build
```

### 2. Initialize Configuration
```bash
make config-init
```

This creates:
- `configs/orchestrator.yaml` - Main orchestrator settings
- `configs/tools/` - Tool-specific configurations

### 3. Test Resource Monitoring
```bash
make monitor
```

### 4. Run a Scan
```bash
./bin/orchestrator scan /path/to/your/project
```

## 📋 Configuration

### Orchestrator Config (`configs/orchestrator.yaml`)
```yaml
orchestrator:
  version: "1.0"

  global:
    timeout_seconds: 1800
    temp_dir: "/tmp/afss-orchestrator"
    log_level: "info"

  resources:
    max_parallel_scans: 2
    memory_limit_percent: 80
    cpu_limit_percent: 70
    adaptive_throttling: true

  execution:
    mode: "resource_aware"
    tool_priority:
      gosec: 1
      semgrep: 2
      trufflehog: 3
```

### Tool Config Example (`configs/tools/gosec.yaml`)
```yaml
tool: gosec
enabled: true
description: "Go static security analysis"

resource_profile:
  memory_peak_mb: 256
  cpu_avg_percent: 50
  expected_duration_seconds: 120

cli:
  severity: medium
  confidence: medium
  no_fail: true
  quiet: true
  output_format: json

conditions:
  - type: file_exists
    pattern: "*.go"
```

## 🛠️ Commands

### Scan Repository
```bash
orchestrator scan /path/to/repo
```

### Profile Tool Resource Usage
```bash
orchestrator profile gosec /path/to/go-repo
```

### Monitor System Resources
```bash
orchestrator monitor
```

### Configuration Management
```bash
orchestrator config init      # Create default configs
orchestrator config validate  # Validate existing configs
```

## 🎯 Key Features

### Resource-Aware Execution
- **Pre-scan Assessment**: Evaluates system capacity before starting
- **Runtime Monitoring**: Tracks CPU, memory, disk usage in real-time
- **Adaptive Throttling**: Reduces parallelism when resources are constrained
- **Graceful Degradation**: Pauses low-priority tools during resource pressure

### Intelligent Scheduling
- **Priority-based Execution**: Critical tools run first
- **Dependency Resolution**: Respects tool dependencies
- **Resource Profiling**: Learns consumption patterns for optimization
- **Parallel Optimization**: Maximizes throughput within resource limits

### Configuration Management
- **YAML-based Configs**: Human-readable and version controllable
- **Validation**: Ensures configuration correctness
- **Dynamic Updates**: Runtime configuration changes
- **Tool-specific Settings**: Individual tool customization

## 🔧 Development

### Prerequisites
- Go 1.23+
- Linux/macOS (Windows support planned)

### Setup Development Environment
```bash
make setup-dev
make dev  # Start development server with hot reload
```

### Run Tests
```bash
make test
```

### Build Docker Image
```bash
make docker-build
make docker-run
```

## 📊 Resource Profiling

The orchestrator includes a profiling system that learns how much resources each tool consumes:

```bash
# Profile a tool on a test repository
orchestrator profile gosec /path/to/test-repo

# Results are saved and used for future scheduling decisions
```

## 🔄 Workflow

1. **Agent Request**: Agent sends scan request with repo path
2. **Resource Assessment**: Check available system resources
3. **Config Loading**: Load tool configurations and resource profiles
4. **Tool Filtering**: Determine which tools can run (based on conditions)
5. **Priority Sorting**: Order tools by priority and resource requirements
6. **Parallel Execution**: Run tools within resource limits
7. **Monitoring**: Track resource usage and adapt as needed
8. **Results Aggregation**: Combine all tool outputs
9. **Response**: Return unified security report to agent

## 🎯 Current Status

### ✅ Implemented
- Resource monitoring system
- YAML configuration management
- Basic CLI interface
- Configuration validation
- Default config generation

### 🚧 In Progress
- Tool execution orchestration
- Resource-aware scheduling
- Results aggregation
- Tool profiling system

### 📋 Planned
- Docker integration
- Advanced error recovery
- Performance optimization
- Additional security tools

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
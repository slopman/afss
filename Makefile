# AFSS Orchestrator Makefile

.PHONY: all build clean test deps run monitor config-init config-validate

# Default target
all: deps build

# Dependencies
deps:
	go mod tidy
	go mod download

# Build the orchestrator
build:
	go build -o bin/orchestrator ./cmd/orchestrator

# Clean build artifacts
clean:
	rm -rf bin/
	rm -f afss-orchestrator

# Run tests
test:
	go test ./...

# Run the orchestrator
run: build
	./bin/orchestrator

# Initialize configurations
config-init: build
	./bin/orchestrator config init

# Validate configurations
config-validate: build
	./bin/orchestrator config validate

# Run resource monitoring demo
monitor: build
	./bin/orchestrator monitor

# Development targets
dev-deps:
	go install github.com/cosmtrek/air@latest

dev:
	air

# Docker targets
docker-build:
	docker build -t afss-orchestrator .

docker-run:
	docker run --rm -v $(PWD):/app afss-orchestrator

# Example usage targets
example-scan: build
	./bin/orchestrator scan /tmp/test-repo

example-profile: build
	./bin/orchestrator profile gosec /tmp/test-repo

# Help
help:
	@echo "AFSS Orchestrator Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  all              - Install deps and build (default)"
	@echo "  deps             - Download Go dependencies"
	@echo "  build            - Build the orchestrator binary"
	@echo "  clean            - Remove build artifacts"
	@echo "  test             - Run Go tests"
	@echo "  run              - Build and run orchestrator"
	@echo "  config-init      - Initialize default configurations"
	@echo "  config-validate  - Validate configuration files"
	@echo "  monitor          - Run resource monitoring demo"
	@echo "  docker-build     - Build Docker image"
	@echo "  docker-run       - Run in Docker container"
	@echo "  help             - Show this help"

# Development setup
setup-dev: dev-deps config-init
	@echo "Development environment ready!"
	@echo "Run 'make dev' to start development server"
	@echo "Run 'make monitor' to test resource monitoring"
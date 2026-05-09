# AFSS Orchestrator Dockerfile
# Isolated image with common security tools + Go (matches go.mod)

FROM golang:1.24-alpine AS tool-builder

# Install build dependencies
RUN apk add --no-cache git make gcc musl-dev python3 py3-pip curl

# Install Security Tools
# 1. Semgrep
RUN pip install --break-system-packages semgrep

# 2. Gosec
RUN go install github.com/securego/gosec/v2/cmd/gosec@latest

# 3. Govulncheck
RUN go install golang.org/x/vuln/cmd/govulncheck@latest

# 4. Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# 5. TruffleHog Go (v3)
RUN go install github.com/trufflesecurity/trufflehog/v3@latest

# 6. Checkov
RUN pip install --break-system-packages checkov

# 7. Bandit
RUN pip install --break-system-packages bandit

# 8. Hadolint
RUN curl -sSfL https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64 -o /usr/local/bin/hadolint && chmod +x /usr/local/bin/hadolint

# --- STAGE 2: Build Orchestrator ---
FROM golang:1.24-alpine

RUN apk add --no-cache python3 py3-pip git curl

# Copy tools from builder
COPY --from=tool-builder /go/bin/gosec /usr/local/bin/
COPY --from=tool-builder /go/bin/govulncheck /usr/local/bin/
COPY --from=tool-builder /go/bin/trufflehog /usr/local/bin/
COPY --from=tool-builder /usr/local/bin/trivy /usr/local/bin/
COPY --from=tool-builder /usr/local/bin/hadolint /usr/local/bin/

# Install python tools in final image
RUN pip install --break-system-packages semgrep bandit checkov

# Setup Orchestrator
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o orchestrator ./cmd/orchestrator

# Default configurations
RUN mkdir -p /app/configs /app/results

ENTRYPOINT ["/app/orchestrator"]
CMD ["--help"]

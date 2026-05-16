# AFSS Orchestrator Dockerfile
# Isolated image with common security tools + Go (matches go.mod)

FROM golang:1.24-alpine AS tool-builder

# Allow toolchain upgrade for tools that declare newer Go (gosec/govulncheck @latest)
ENV GOTOOLCHAIN=auto

# Install build dependencies
RUN apk add --no-cache git make gcc musl-dev python3 py3-pip curl

# Install Security Tools
# 1. Semgrep
RUN pip install --break-system-packages semgrep

# 2. Gosec
RUN go install github.com/securego/gosec/v2/cmd/gosec@latest

# 2b. Gitleaks
RUN curl -fsSL https://github.com/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_linux_x64.tar.gz | tar xz -C /usr/local/bin gitleaks && chmod +x /usr/local/bin/gitleaks

# 3. Govulncheck
RUN go install golang.org/x/vuln/cmd/govulncheck@latest

# 4. Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# 5. TruffleHog — release binary (go install fails on upstream replace directives)
RUN curl -fsSL https://github.com/trufflesecurity/trufflehog/releases/download/v3.95.3/trufflehog_3.95.3_linux_amd64.tar.gz | tar xz -C /usr/local/bin trufflehog && chmod +x /usr/local/bin/trufflehog

# 6. Checkov
RUN pip install --break-system-packages checkov

# 7. Bandit
RUN pip install --break-system-packages bandit

# 7b. njsscan (Node.js SAST)
RUN pip install --break-system-packages njsscan

# 7c. OSV-Scanner (release binary)
ARG OSV_SCANNER_VER=v2.2.4
RUN curl -fsSL "https://github.com/google/osv-scanner/releases/download/${OSV_SCANNER_VER}/osv-scanner_linux_amd64" -o /usr/local/bin/osv-scanner && chmod +x /usr/local/bin/osv-scanner

# 7d. OWASP Dependency-Check (needs JRE + bash)
ARG DC_VER=12.1.0
RUN apk add --no-cache openjdk17-jre-headless bash unzip \
 && curl -fsSL "https://github.com/jeremylong/DependencyCheck/releases/download/v${DC_VER}/dependency-check-${DC_VER}-release.zip" -o /tmp/dc.zip \
 && unzip -q /tmp/dc.zip -d /opt \
 && ln -sf /opt/dependency-check/bin/dependency-check.sh /usr/local/bin/dependency-check.sh \
 && rm -f /tmp/dc.zip

# 8. Hadolint
RUN curl -sSfL https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64 -o /usr/local/bin/hadolint && chmod +x /usr/local/bin/hadolint

# --- STAGE 2: Build Orchestrator ---
FROM golang:1.24-alpine

ENV GOTOOLCHAIN=auto

RUN apk add --no-cache python3 py3-pip git curl openjdk17-jre-headless bash \
 && git config --system --add safe.directory '*' \
 && mkdir -p /tmp/dependency-check-data

# Copy tools from builder
COPY --from=tool-builder /go/bin/gosec /usr/local/bin/
COPY --from=tool-builder /go/bin/govulncheck /usr/local/bin/
COPY --from=tool-builder /usr/local/bin/trufflehog /usr/local/bin/trufflehog
COPY --from=tool-builder /usr/local/bin/trivy /usr/local/bin/
COPY --from=tool-builder /usr/local/bin/hadolint /usr/local/bin/
COPY --from=tool-builder /usr/local/bin/gitleaks /usr/local/bin/
COPY --from=tool-builder /usr/local/bin/osv-scanner /usr/local/bin/
COPY --from=tool-builder /opt/dependency-check /opt/dependency-check
RUN ln -sf /opt/dependency-check/bin/dependency-check.sh /usr/local/bin/dependency-check.sh

# Install python tools in final image
RUN pip install --break-system-packages semgrep bandit checkov njsscan

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

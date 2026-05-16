package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/security-scanner/afss-orchestrator/pkg/executor"
	"github.com/security-scanner/afss-orchestrator/pkg/models"
	"github.com/security-scanner/afss-orchestrator/pkg/tools/runners"
	"github.com/security-scanner/afss-orchestrator/pkg/util"
)

// Runner executes security tools based on their configurations
type Runner struct {
	logger   *logrus.Logger
	executor *executor.AdaptiveExecutor
}

// NewRunner creates a new tool runner
func NewRunner(logger *logrus.Logger, executor *executor.AdaptiveExecutor) *Runner {
	return &Runner{
		logger:   logger,
		executor: executor,
	}
}

// ValidateTools checks if all enabled tools are available in the system or local tools directory
func (r *Runner) ValidateTools(configs map[string]*models.ToolConfig) map[string]bool {
	status := make(map[string]bool)
	for toolName, cfg := range configs {
		if !cfg.Enabled {
			continue
		}
		_, err := r.findCommand(toolName, []string{})
		status[toolName] = (err == nil)
	}
	return status
}

// RunTool executes a security tool with the given configuration
func (r *Runner) RunTool(ctx context.Context, toolConfig *models.ToolConfig, repoPath string) (*models.ToolResult, error) {
	startTime := time.Now()

	result := &models.ToolResult{
		ToolName:  toolConfig.Tool,
		Status:    models.StatusRunning,
		StartTime: startTime,
		ResourceUsage: []models.ResourceSnapshot{},
	}

	r.logger.WithFields(logrus.Fields{"tool": toolConfig.Tool, "repo": repoPath}).Info("Starting tool execution")

	if toolConfig.Tool == "gitleaks" {
		_ = os.Remove(runners.GitleaksReportPathForRead(toolConfig, repoPath))
	}

	// Build command arguments from config
	args, err := r.buildCommandArgs(toolConfig, repoPath)
	if err != nil {
		result.Status = models.StatusFailed
		result.EndTime = time.Now()
		result.Duration = time.Since(startTime)
		result.Error = err.Error()
		return result, fmt.Errorf("failed to build command: %w", err)
	}

	// Find command and binary path
	cmd, err := r.findCommand(toolConfig.Tool, args)
	if err != nil {
		result.Status = models.StatusFailed
		result.EndTime = time.Now()
		result.Duration = time.Since(startTime)
		result.Error = fmt.Sprintf("binary not found: %v", err)
		return result, fmt.Errorf("tool binary not found: %w", err)
	}

	if toolConfig.Tool == "owasp-dep-check" {
		outDir := runners.OwaspOutputDir(toolConfig, repoPath)
		if mkErr := os.MkdirAll(outDir, 0755); mkErr != nil {
			r.logger.Warnf("OWASP Dependency-Check: could not create output directory %s: %v", outDir, mkErr)
		}
		if mkErr := os.MkdirAll(runners.OwaspDataDir(toolConfig), 0755); mkErr != nil {
			r.logger.Warnf("OWASP Dependency-Check: could not create data directory: %v", mkErr)
		}
	}

	// Execute the tool using AdaptiveExecutor if available
	var output string
	if r.executor != nil {
		output, err = r.executor.ExecuteTool(ctx, toolConfig.Tool, cmd.Path, args, repoPath)
	} else {
		// Fallback to legacy execution if no executor defined
		output, err = r.executeCommandWithCmd(ctx, toolConfig.Tool, cmd)
	}

	result.EndTime = time.Now()
	result.Duration = time.Since(startTime)

	// Check if the error is an expected exit code (e.g., findings found)
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if r.isExpectedExitCode(toolConfig.Tool, exitErr.ExitCode()) {
				err = nil
				r.logger.Infof("Tool %s exited with code %d (expected, findings found)", toolConfig.Tool, exitErr.ExitCode())
			}
		}
	}

	// Gitleaks v8+ writes the report to -r only; stdout is log lines.
	if toolConfig.Tool == "gitleaks" {
		reportPath := runners.GitleaksReportPathForRead(toolConfig, repoPath)
		if data, readErr := os.ReadFile(reportPath); readErr == nil && len(data) > 0 {
			t := strings.TrimSpace(string(data))
			if strings.HasPrefix(t, "[") || strings.HasPrefix(t, "{") {
				output = string(data)
			}
		} else if readErr != nil && !os.IsNotExist(readErr) {
			r.logger.Warnf("Gitleaks: could not read report at %s: %v", reportPath, readErr)
		}
	}

	// OWASP Dependency-Check writes JSON to a file; recover when a report exists despite non-zero exit
	if toolConfig.Tool == "owasp-dep-check" {
		reportPath := runners.OwaspReportJSONPath(toolConfig, repoPath)
		if data, readErr := os.ReadFile(reportPath); readErr == nil && len(data) > 0 && json.Valid(data) {
			output = string(data)
			if err != nil {
				r.logger.Warnf("OWASP Dependency-Check: recovered JSON report at %s after error: %v", reportPath, err)
				err = nil
			}
		} else if err == nil && readErr != nil {
			r.logger.Warnf("OWASP Dependency-Check: could not read JSON report at %s: %v", reportPath, readErr)
		}
	}

	if err != nil {
		result.Status = models.StatusFailed
		result.Error = err.Error()
		r.logger.WithFields(logrus.Fields{"tool": toolConfig.Tool, "error": err}).Warn("Tool execution failed")
	} else {
		result.Status = models.StatusCompleted
		result.Output = output

		// Try to parse results if output looks like JSON
		trimOut := strings.TrimSpace(output)
		parseIn := trimOut
		if toolConfig.Tool != "govulncheck" {
			if j := util.FirstJSONValue(trimOut); j != "" {
				parseIn = j
			}
		}
		if parseIn != "" && (strings.HasPrefix(strings.TrimSpace(parseIn), "{") || strings.HasPrefix(strings.TrimSpace(parseIn), "[")) {
			findings, parseErr := r.parseJSONFindings(parseIn, toolConfig.Tool)
			if parseErr != nil {
				r.logger.WithFields(logrus.Fields{"tool": toolConfig.Tool, "error": parseErr}).Warn("Failed to parse tool output")
			} else {
				result.Findings = findings
			}
		}

		r.logger.WithFields(logrus.Fields{"tool": toolConfig.Tool, "findings": len(result.Findings)}).Info("Tool execution completed")
	}

	return result, nil
}

// buildCommandArgs builds command line arguments from tool configuration
func (r *Runner) buildCommandArgs(config *models.ToolConfig, repoPath string) ([]string, error) {
	switch config.Tool {
	case "gosec":
		return runners.BuildGosecArgs(config, repoPath)
	case "semgrep":
		return runners.BuildSemgrepArgs(config, repoPath)
	case "trufflehog":
		return runners.BuildTruffleHogArgs(config, repoPath)
	case "owasp-dep-check":
		return runners.BuildOWASPDepCheckArgs(config, repoPath)
	case "govulncheck":
		return runners.BuildGovulncheckArgs(config, repoPath)
	case "trivy":
		return runners.BuildTrivyArgs(config, repoPath)
	case "checkov":
		return runners.BuildCheckovArgs(config, repoPath)
	case "hadolint":
		return runners.BuildHadolintArgs(config, repoPath)
	case "gitleaks":
		return runners.BuildGitleaksArgs(config, repoPath)
	case "osv-scanner":
		return runners.BuildOSVScannerArgs(config, repoPath)
	case "bandit":
		return runners.BuildBanditArgs(config, repoPath)
	case "njsscan":
		return runners.BuildNjsscanArgs(config, repoPath)
	default:
		return nil, fmt.Errorf("unsupported tool: %s", config.Tool)
	}
}

// executeCommandWithCmd runs the actual command using provided Cmd object
func (r *Runner) executeCommandWithCmd(ctx context.Context, toolName string, cmd *exec.Cmd) (string, error) {
	r.logger.WithField("command", cmd.String()).Debug("Executing command")

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Some tools return non-zero exit codes when findings are found
		if exitErr, ok := err.(*exec.ExitError); ok {
			// For tools like gosec, semgrep, etc., findings are expected
			if r.isExpectedExitCode(toolName, exitErr.ExitCode()) {
				return string(output), nil
			}
		}
		return "", err
	}

	return string(output), nil
}

// findCommand finds the executable for the given tool
func (r *Runner) findCommand(toolName string, args []string) (*exec.Cmd, error) {
	// 1. Try to find in local tools directory
	localBins := map[string]string{
		"gosec":           filepath.Join("tools", "gosec", "gosec"),
		"semgrep":         filepath.Join("tools", "semgrep", "venv", "bin", "semgrep"),
		"trufflehog":      filepath.Join("tools", "trufflehog", "trufflehog"), // Correcting path based on find
		"govulncheck":     filepath.Join("tools", "govulncheck", "govulncheck"),
		"trivy":           filepath.Join("tools", "trivy", "trivy"),
		"checkov":         filepath.Join("tools", "checkov", "bin", "checkov"),
		"hadolint":        filepath.Join("tools", "hadolint", "hadolint"),
		"gitleaks":        filepath.Join("tools", "gitleaks", "gitleaks"),
		"osv-scanner":     filepath.Join("tools", "osv-scanner", "osv-scanner"),
		"bandit":          filepath.Join("tools", "bandit", "venv", "bin", "bandit"),
		"njsscan":         filepath.Join("tools", "njsscan", "venv", "bin", "njsscan"),
		"dependency-check": filepath.Join("tools", "dependency-check", "bin", "dependency-check.sh"),
	}

	if localPath, ok := localBins[toolName]; ok {
		// Try relative to current dir
		if _, err := os.Stat(localPath); err == nil {
			absPath, _ := filepath.Abs(localPath)
			return exec.Command(absPath, args...), nil
		}
	}

	// 2. Fallback to global PATH
	path, err := exec.LookPath(toolName)
	if err == nil {
		return exec.Command(path, args...), nil
	}

	// Special case for dependency-check global name
	if toolName == "owasp-dep-check" {
		path, err = exec.LookPath("dependency-check.sh")
		if err == nil {
			return exec.Command(path, args...), nil
		}
	}

	return nil, fmt.Errorf("tool binary not found: %s", toolName)
}

// isExpectedExitCode checks if the exit code is expected for the tool
func (r *Runner) isExpectedExitCode(toolName string, code int) bool {
	switch toolName {
	case "gosec", "semgrep", "trufflehog", "owasp-dep-check", "govulncheck", "trivy", "checkov", "hadolint", "gitleaks", "osv-scanner", "bandit", "njsscan":
		// These tools often exit with code 1 when findings are found
		return code == 1
	default:
		return false
	}
}

// parseJSONFindings parses JSON output into findings
func (r *Runner) parseJSONFindings(output, toolName string) ([]models.Finding, error) {
	switch toolName {
	case "gosec":
		return runners.ParseGosecFindings(output)
	case "semgrep":
		return runners.ParseSemgrepFindings(output)
	case "trufflehog":
		return runners.ParseTruffleHogFindings(output)
	case "owasp-dep-check":
		return runners.ParseOWASPFindings(output)
	case "govulncheck":
		return runners.ParseGovulncheckFindings(output)
	case "trivy":
		return runners.ParseTrivyFindings(output)
	case "checkov":
		return runners.ParseCheckovFindings(output)
	case "hadolint":
		return runners.ParseHadolintFindings(output)
	case "gitleaks":
		return runners.ParseGitleaksFindings(output)
	case "osv-scanner":
		return runners.ParseOSVScannerFindings(output)
	case "bandit":
		return runners.ParseBanditFindings(output)
	case "njsscan":
		return runners.ParseNjsscanFindings(output)
	default:
		return []models.Finding{}, nil
	}
}

// Build arguments for specific tools






// Parse findings from specific tools



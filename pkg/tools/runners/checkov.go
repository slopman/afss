package runners

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/security-scanner/afss-orchestrator/pkg/models"
)

// buildCheckovArgs builds command line arguments for Checkov
func BuildCheckovArgs(config *models.ToolConfig, repoPath string) ([]string, error) {
	args := []string{}

	// Input sources - directory or file (not both)
	if directory, ok := config.CLI["directory"].(string); ok && directory != "" {
		args = append(args, "-d", directory)
	} else if files, ok := config.CLI["file"].([]interface{}); ok && len(files) > 0 {
		for _, file := range files {
			if fileStr, ok := file.(string); ok {
				args = append(args, "-f", fileStr)
			}
		}
	} else {
		// Default to repo path
		args = append(args, "-d", repoPath)
	}

	// Output format (-o json|sarif|... ; omit only for human "cli" default)
	if output, ok := config.CLI["output"].(string); ok && output != "" && output != "cli" {
		args = append(args, "-o", output)
	}

	// Output file path
	if outputFile, ok := config.CLI["output_file_path"].(string); ok && outputFile != "" {
		args = append(args, "--output-file-path", outputFile)
	}

	// Output options
	if outputBcIds, ok := config.CLI["output_bc_ids"].(bool); ok && outputBcIds {
		args = append(args, "--output-bc-ids")
	}

	if includeAll, ok := config.CLI["include_all_checkov_policies"].(bool); ok && includeAll {
		args = append(args, "--include-all-checkov-policies")
	}

	// Formatting options
	if quiet, ok := config.CLI["quiet"].(bool); ok && quiet {
		args = append(args, "--quiet")
	}

	if compact, ok := config.CLI["compact"].(bool); ok && compact {
		args = append(args, "--compact")
	}

	// Framework selection
	if frameworks, ok := config.CLI["framework"].([]interface{}); ok && len(frameworks) > 0 {
		for _, fw := range frameworks {
			if fwStr, ok := fw.(string); ok {
				args = append(args, "--framework", fwStr)
			}
		}
	}

	if skipFrameworks, ok := config.CLI["skip_framework"].([]interface{}); ok && len(skipFrameworks) > 0 {
		for _, fw := range skipFrameworks {
			if fwStr, ok := fw.(string); ok {
				args = append(args, "--skip-framework", fwStr)
			}
		}
	}

	// Check selection and filtering
	if check, ok := config.CLI["check"].(string); ok && check != "" {
		args = append(args, "-c", check)
	}

	if skipCheck, ok := config.CLI["skip_check"].(string); ok && skipCheck != "" {
		args = append(args, "--skip-check", skipCheck)
	}

	if runAllExternal, ok := config.CLI["run_all_external_checks"].(bool); ok && runAllExternal {
		args = append(args, "--run-all-external-checks")
	}

	// Path filtering
	if skipPath, ok := config.CLI["skip_path"].(string); ok && skipPath != "" {
		args = append(args, "--skip-path", skipPath)
	}

	// External checks
	if externalDir, ok := config.CLI["external_checks_dir"].(string); ok && externalDir != "" {
		args = append(args, "--external-checks-dir", externalDir)
	}

	if externalGits, ok := config.CLI["external_checks_git"].([]interface{}); ok && len(externalGits) > 0 {
		for _, git := range externalGits {
			if gitStr, ok := git.(string); ok {
				args = append(args, "--external-checks-git", gitStr)
			}
		}
	}

	// Failure handling
	if softFail, ok := config.CLI["soft_fail"].(bool); ok && softFail {
		args = append(args, "-s")
	}

	if softFailOn, ok := config.CLI["soft_fail_on"].(string); ok && softFailOn != "" {
		args = append(args, "--soft-fail-on", softFailOn)
	}

	if hardFailOn, ok := config.CLI["hard_fail_on"].(string); ok && hardFailOn != "" {
		args = append(args, "--hard-fail-on", hardFailOn)
	}

	// Bridgecrew/Prisma Cloud integration
	if bcApiKey, ok := config.CLI["bc_api_key"].(string); ok && bcApiKey != "" {
		args = append(args, "--bc-api-key", bcApiKey)
	}

	if prismaUrl, ok := config.CLI["prisma_api_url"].(string); ok && prismaUrl != "" {
		args = append(args, "--prisma-api-url", prismaUrl)
	}

	if skipUpload, ok := config.CLI["skip_results_upload"].(bool); ok && skipUpload {
		args = append(args, "--skip-results-upload")
	}

	// Docker scanning
	if dockerImage, ok := config.CLI["docker_image"].(string); ok && dockerImage != "" {
		args = append(args, "--docker-image", dockerImage)
	}

	if dockerfilePath, ok := config.CLI["dockerfile_path"].(string); ok && dockerfilePath != "" {
		args = append(args, "--dockerfile-path", dockerfilePath)
	}

	// Repository settings
	if repoId, ok := config.CLI["repo_id"].(string); ok && repoId != "" {
		args = append(args, "--repo-id", repoId)
	}

	if branch, ok := config.CLI["branch"].(string); ok && branch != "" {
		args = append(args, "-b", branch)
	}

	// Module handling
	if skipDownload, ok := config.CLI["skip_download"].(bool); ok && skipDownload {
		args = append(args, "--skip-download")
	}

	if useEnforcement, ok := config.CLI["use_enforcement_rules"].(bool); ok && useEnforcement {
		args = append(args, "--use-enforcement-rules")
	}

	if downloadModules, ok := config.CLI["download_external_modules"].(string); ok && downloadModules != "" {
		args = append(args, "--download-external-modules", downloadModules)
	}

	if varFile, ok := config.CLI["var_file"].(string); ok && varFile != "" {
		args = append(args, "--var-file", varFile)
	}

	if externalModulesPath, ok := config.CLI["external_modules_download_path"].(string); ok && externalModulesPath != "" {
		args = append(args, "--external-modules-download-path", externalModulesPath)
	}

	if evaluateVars, ok := config.CLI["evaluate_variables"].(string); ok && evaluateVars != "" {
		args = append(args, "--evaluate-variables", evaluateVars)
	}

	// SSL/TLS settings
	if caCert, ok := config.CLI["ca_certificate"].(string); ok && caCert != "" {
		args = append(args, "-ca", caCert)
	}

	if noCertVerify, ok := config.CLI["no_cert_verify"].(bool); ok && noCertVerify {
		args = append(args, "--no-cert-verify")
	}

	// Plan enrichment
	if repoRoot, ok := config.CLI["repo_root_for_plan_enrichment"].(string); ok && repoRoot != "" {
		args = append(args, "--repo-root-for-plan-enrichment", repoRoot)
	}

	// Configuration management
	if configFile, ok := config.CLI["config_file"].(string); ok && configFile != "" {
		args = append(args, "--config-file", configFile)
	}

	if createConfig, ok := config.CLI["create_config"].(string); ok && createConfig != "" {
		args = append(args, "--create-config", createConfig)
	}

	if showConfig, ok := config.CLI["show_config"].(bool); ok && showConfig {
		args = append(args, "--show-config")
	}

	// Baseline management
	if createBaseline, ok := config.CLI["create_baseline"].(bool); ok && createBaseline {
		args = append(args, "--create-baseline")
	}

	if baseline, ok := config.CLI["baseline"].(string); ok && baseline != "" {
		args = append(args, "--baseline", baseline)
	}

	if outputBaselineAsSkipped, ok := config.CLI["output_baseline_as_skipped"].(bool); ok && outputBaselineAsSkipped {
		args = append(args, "--output-baseline-as-skipped")
	}

	// CVE handling
	if skipCvePackage, ok := config.CLI["skip_cve_package"].(string); ok && skipCvePackage != "" {
		args = append(args, "--skip-cve-package", skipCvePackage)
	}

	// Policy filtering
	if policyFilter, ok := config.CLI["policy_metadata_filter"].(string); ok && policyFilter != "" {
		args = append(args, "--policy-metadata-filter", policyFilter)
	}

	if policyFilterException, ok := config.CLI["policy_metadata_filter_exception"].(string); ok && policyFilterException != "" {
		args = append(args, "--policy-metadata-filter-exception", policyFilterException)
	}

	// Secrets scanning
	if secretFileTypes, ok := config.CLI["secrets_scan_file_type"].([]interface{}); ok && len(secretFileTypes) > 0 {
		for _, ft := range secretFileTypes {
			if ftStr, ok := ft.(string); ok {
				args = append(args, "--secrets-scan-file-type", ftStr)
			}
		}
	}

	if enableSecretScanAll, ok := config.CLI["enable_secret_scan_all_files"].(bool); ok && enableSecretScanAll {
		args = append(args, "--enable-secret-scan-all-files")
	}

	if blockListSecret, ok := config.CLI["block_list_secret_scan"].(string); ok && blockListSecret != "" {
		args = append(args, "--block-list-secret-scan", blockListSecret)
	}

	if scanSecretsHistory, ok := config.CLI["scan_secrets_history"].(bool); ok && scanSecretsHistory {
		args = append(args, "--scan-secrets-history")
	}

	if secretsTimeout, ok := config.CLI["secrets_history_timeout"].(int); ok && secretsTimeout > 0 {
		args = append(args, "--secrets-history-timeout", fmt.Sprintf("%d", secretsTimeout))
	}

	// Output customization
	if summaryPos, ok := config.CLI["summary_position"].(string); ok && summaryPos != "" {
		args = append(args, "--summary-position", summaryPos)
	}

	if skipResourcesWithoutViolations, ok := config.CLI["skip_resources_without_violations"].(bool); ok && skipResourcesWithoutViolations {
		args = append(args, "--skip-resources-without-violations")
	}

	// Analysis options
	if deepAnalysis, ok := config.CLI["deep_analysis"].(bool); ok && deepAnalysis {
		args = append(args, "--deep-analysis")
	}

	if noFailOnCrash, ok := config.CLI["no_fail_on_crash"].(bool); ok && noFailOnCrash {
		args = append(args, "--no-fail-on-crash")
	}

	if masks, ok := config.CLI["mask"].([]interface{}); ok && len(masks) > 0 {
		for _, mask := range masks {
			if maskStr, ok := mask.(string); ok {
				args = append(args, "--mask", maskStr)
			}
		}
	}

	// Custom tool name
	if customToolName, ok := config.CLI["custom_tool_name"].(string); ok && customToolName != "" {
		args = append(args, "--custom-tool-name", customToolName)
	}

	// Special flags
	if list, ok := config.CLI["list"].(bool); ok && list {
		args = append(args, "-l")
	}

	if support, ok := config.CLI["support"].(bool); ok && support {
		args = append(args, "--support")
	}

	if addCheck, ok := config.CLI["add_check"].(bool); ok && addCheck {
		args = append(args, "--add-check")
	}

	return args, nil
}

// parseCheckovFindings parses Checkov JSON output into findings
func ParseCheckovFindings(output string) ([]models.Finding, error) {
	var findings []models.Finding

	// Checkov has complex JSON structure depending on output format
	// Try to parse as different formats

	// First try standard checkov format
	var checkovResult struct {
		Results struct {
			FailedChecks []struct {
				CheckID       string                 `json:"check_id"`
				CheckName     string                 `json:"check_name"`
				FilePath      string                 `json:"file_path"`
				FileLineRange  []int                  `json:"file_line_range"`
				Resource      string                 `json:"resource"`
				Evaluations   map[string]interface{} `json:"evaluations"`
				CheckType     string                 `json:"check_type"`
				BcCheckId     string                 `json:"bc_check_id"`
				Severity      string                 `json:"severity"`
				Category      string                 `json:"category"`
				Guideline     string                 `json:"guideline"`
			} `json:"failed_checks"`
		} `json:"results"`
		Summary struct {
			PassedChecks  int `json:"passed_checks"`
			FailedChecks  int `json:"failed_checks"`
			SkippedChecks int `json:"skipped_checks"`
		} `json:"summary"`
	}

	if err := json.Unmarshal([]byte(output), &checkovResult); err == nil {
		for _, check := range checkovResult.Results.FailedChecks {
			finding := models.Finding{
				ID:          fmt.Sprintf("checkov-%s-%s", check.CheckID, check.Resource),
				Title:       check.CheckName,
				Description: check.CheckName,
				Severity:    convertCheckovSeverity(check.Severity),
				File:        check.FilePath,
				Line:         check.FileLineRange[0],
				Category:    check.Category,
				RuleID:      check.CheckID,
				Tool:        "checkov",
				Tags:        []string{"checkov", check.CheckType, check.Category},
			}
			findings = append(findings, finding)
		}
		return findings, nil
	}

	// Try alternative format (simpler)
	var simpleResult []struct {
		CheckID   string `json:"check_id"`
		CheckName string `json:"check_name"`
		FilePath  string `json:"file_path"`
		Resource  string `json:"resource"`
		Severity  string `json:"severity"`
	}

	if err := json.Unmarshal([]byte(output), &simpleResult); err == nil {
		for _, check := range simpleResult {
			finding := models.Finding{
				ID:          fmt.Sprintf("checkov-%s-%s", check.CheckID, check.Resource),
				Title:       check.CheckName,
				Description: check.CheckName,
				Severity:    convertCheckovSeverity(check.Severity),
				File:        check.FilePath,
				Category:    "iac",
				RuleID:      check.CheckID,
				Tool:        "checkov",
				Tags:        []string{"checkov", "iac"},
			}
			findings = append(findings, finding)
		}
		return findings, nil
	}

	// If JSON parsing fails, return empty findings (checkov might have different output format)
	return []models.Finding{}, nil
}

// convertCheckovSeverity converts Checkov severity to standard format
func convertCheckovSeverity(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	case "INFO":
		return "info"
	default:
		return "medium"
	}
}
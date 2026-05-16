package runners

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/security-scanner/afss-orchestrator/pkg/models"
)

// buildSemgrepArgs builds command line arguments for Semgrep
func BuildSemgrepArgs(config *models.ToolConfig, repoPath string) ([]string, error) {
	args := []string{}

	// Configuration - Path to config file or registry entry (e.g., "auto", "p/ci", ".semgrep.yml")
	if configVal, ok := config.CLI["config"].(string); ok && configVal != "" {
		args = append(args, "--config", configVal)
	}

	// Output formats - Multiple formats can be enabled
	if json, ok := config.CLI["json"].(bool); ok && json {
		args = append(args, "--json")
	}

	if sarif, ok := config.CLI["sarif"].(bool); ok && sarif {
		args = append(args, "--sarif")
	}

	if junitXML, ok := config.CLI["junit_xml"].(bool); ok && junitXML {
		args = append(args, "--junit-xml")
	}

	if gitlabSAST, ok := config.CLI["gitlab_sast"].(bool); ok && gitlabSAST {
		args = append(args, "--gitlab-sast")
	}

	if gitlabSecrets, ok := config.CLI["gitlab_secrets"].(bool); ok && gitlabSecrets {
		args = append(args, "--gitlab-secrets")
	}

	if text, ok := config.CLI["text"].(bool); ok && text {
		args = append(args, "--text")
	}

	// Output file paths - Specify custom output file paths
	if output, ok := config.CLI["output"].(string); ok && output != "" {
		args = append(args, "--output", output)
	}

	if jsonOutput, ok := config.CLI["json_output"].(string); ok && jsonOutput != "" {
		args = append(args, "--json-output", jsonOutput)
	}

	if sarifOutput, ok := config.CLI["sarif_output"].(string); ok && sarifOutput != "" {
		args = append(args, "--sarif-output", sarifOutput)
	}

	if junitXMLOutput, ok := config.CLI["junit_xml_output"].(string); ok && junitXMLOutput != "" {
		args = append(args, "--junit-xml-output", junitXMLOutput)
	}

	if gitlabSASTOutput, ok := config.CLI["gitlab_sast_output"].(string); ok && gitlabSASTOutput != "" {
		args = append(args, "--gitlab-sast-output", gitlabSASTOutput)
	}

	if gitlabSecretsOutput, ok := config.CLI["gitlab_secrets_output"].(string); ok && gitlabSecretsOutput != "" {
		args = append(args, "--gitlab-secrets-output", gitlabSecretsOutput)
	}

	if textOutput, ok := config.CLI["text_output"].(string); ok && textOutput != "" {
		args = append(args, "--text-output", textOutput)
	}

	if emacs, ok := config.CLI["emacs"].(bool); ok && emacs {
		args = append(args, "--emacs")
	}

	if emacsOutput, ok := config.CLI["emacs_output"].(string); ok && emacsOutput != "" {
		args = append(args, "--emacs-output", emacsOutput)
	}

	if vim, ok := config.CLI["vim"].(bool); ok && vim {
		args = append(args, "--vim")
	}

	if vimOutput, ok := config.CLI["vim_output"].(string); ok && vimOutput != "" {
		args = append(args, "--vim-output", vimOutput)
	}

	// Behavior controls
	if dryRun, ok := config.CLI["dry_run"].(bool); ok && dryRun {
		args = append(args, "--dry-run")
	}

	if verbose, ok := config.CLI["verbose"].(bool); ok && verbose {
		args = append(args, "--verbose")
	}

	if debug, ok := config.CLI["debug"].(bool); ok && debug {
		args = append(args, "--debug")
	}

	if quiet, ok := config.CLI["quiet"].(bool); ok && quiet {
		args = append(args, "--quiet")
	}

	if error, ok := config.CLI["error"].(bool); ok && error {
		args = append(args, "--error")
	}

	if continueOnError, ok := config.CLI["continue_on_error"].(bool); ok && continueOnError {
		args = append(args, "--continue-on-error")
	}

	if noError, ok := config.CLI["no_error"].(bool); ok && noError {
		args = append(args, "--no-error")
	}

	if strict, ok := config.CLI["strict"].(bool); ok && strict {
		args = append(args, "--strict")
	}

	if noStrict, ok := config.CLI["no_strict"].(bool); ok && noStrict {
		args = append(args, "--no-strict")
	}

	if forceColor, ok := config.CLI["force_color"].(bool); ok && forceColor {
		args = append(args, "--force-color")
	}

	if noForceColor, ok := config.CLI["no_force_color"].(bool); ok && noForceColor {
		args = append(args, "--no-force-color")
	}

	// Performance tuning
	if maxTargetBytes, ok := config.CLI["max_target_bytes"].(int); ok && maxTargetBytes > 0 {
		args = append(args, "--max-target-bytes", fmt.Sprintf("%d", maxTargetBytes))
	}

	if jobs, ok := config.CLI["jobs"].(int); ok && jobs > 0 {
		args = append(args, "--jobs", fmt.Sprintf("%d", jobs))
	}

	if maxMemory, ok := config.CLI["max_memory"].(int); ok && maxMemory > 0 {
		args = append(args, "--max-memory", fmt.Sprintf("%d", maxMemory))
	}

	if timeout, ok := config.CLI["timeout"].(float64); ok && timeout > 0 {
		args = append(args, "--timeout", fmt.Sprintf("%.1f", timeout))
	}

	if timeoutThreshold, ok := config.CLI["timeout_threshold"].(int); ok && timeoutThreshold > 0 {
		args = append(args, "--timeout-threshold", fmt.Sprintf("%d", timeoutThreshold))
	}

	if interfileTimeout, ok := config.CLI["interfile_timeout"].(int); ok && interfileTimeout > 0 {
		args = append(args, "--interfile-timeout", fmt.Sprintf("%d", interfileTimeout))
	}

	if maxCharsPerLine, ok := config.CLI["max_chars_per_line"].(int); ok && maxCharsPerLine > 0 {
		args = append(args, "--max-chars-per-line", fmt.Sprintf("%d", maxCharsPerLine))
	}

	if maxLinesPerFinding, ok := config.CLI["max_lines_per_finding"].(int); ok && maxLinesPerFinding > 0 {
		args = append(args, "--max-lines-per-finding", fmt.Sprintf("%d", maxLinesPerFinding))
	}

	if maxLogListEntries, ok := config.CLI["max_log_list_entries"].(int); ok && maxLogListEntries > 0 {
		args = append(args, "--max-log-list-entries", fmt.Sprintf("%d", maxLogListEntries))
	}

	// Path filtering
	if include, ok := config.CLI["include"].([]interface{}); ok && len(include) > 0 {
		for _, pattern := range include {
			if patternStr, ok := pattern.(string); ok {
				args = append(args, "--include", patternStr)
			}
		}
	}

	if exclude, ok := config.CLI["exclude"].([]interface{}); ok && len(exclude) > 0 {
		for _, pattern := range exclude {
			if patternStr, ok := pattern.(string); ok {
				args = append(args, "--exclude", patternStr)
			}
		}
	}

	if baselineCommit, ok := config.CLI["baseline_commit"].(string); ok && baselineCommit != "" {
		args = append(args, "--baseline-commit", baselineCommit)
	}

	if scanUnknownExtensions, ok := config.CLI["scan_unknown_extensions"].(bool); ok && scanUnknownExtensions {
		args = append(args, "--scan-unknown-extensions")
	}

	if skipUnknownExtensions, ok := config.CLI["skip_unknown_extensions"].(bool); ok && skipUnknownExtensions {
		args = append(args, "--skip-unknown-extensions")
	}

	if excludeMinifiedFiles, ok := config.CLI["exclude_minified_files"].(bool); ok && excludeMinifiedFiles {
		args = append(args, "--exclude-minified-files")
	}

	if noExcludeMinifiedFiles, ok := config.CLI["no_exclude_minified_files"].(bool); ok && noExcludeMinifiedFiles {
		args = append(args, "--no-exclude-minified-files")
	}

	if useGitIgnore, ok := config.CLI["use_git_ignore"].(bool); ok && useGitIgnore {
		args = append(args, "--use-git-ignore")
	}

	if noGitIgnore, ok := config.CLI["no_git_ignore"].(bool); ok && noGitIgnore {
		args = append(args, "--no-git-ignore")
	}

	if novcs, ok := config.CLI["novcs"].(bool); ok && novcs {
		args = append(args, "--novcs")
	}

	// Code analysis features
	if pattern, ok := config.CLI["pattern"].(string); ok && pattern != "" {
		args = append(args, "--pattern", pattern)
	}

	if lang, ok := config.CLI["lang"].(string); ok && lang != "" {
		args = append(args, "--lang", lang)
	}

	if dataflowTraces, ok := config.CLI["dataflow_traces"].(bool); ok && dataflowTraces {
		args = append(args, "--dataflow-traces")
	}

	if matchingExplanations, ok := config.CLI["matching_explanations"].(bool); ok && matchingExplanations {
		args = append(args, "--matching-explanations")
	}

	if dumpAST, ok := config.CLI["dump_ast"].(bool); ok && dumpAST {
		args = append(args, "--dump-ast")
	}

	// Autofix features - EXPERIMENTAL
	if autofix, ok := config.CLI["autofix"].(bool); ok && autofix {
		args = append(args, "--autofix")
	}

	if noAutofix, ok := config.CLI["no_autofix"].(bool); ok && noAutofix {
		args = append(args, "--no-autofix")
	}

	if replacement, ok := config.CLI["replacement"].(string); ok && replacement != "" {
		args = append(args, "--replacement", replacement)
	}

	if dryrun, ok := config.CLI["dryrun"].(bool); ok && dryrun {
		args = append(args, "--dryrun")
	}

	if noDryrun, ok := config.CLI["no_dryrun"].(bool); ok && noDryrun {
		args = append(args, "--no-dryrun")
	}

	// Rules management
	if enableRules, ok := config.CLI["enable_rule"].([]interface{}); ok && len(enableRules) > 0 {
		for _, rule := range enableRules {
			if ruleStr, ok := rule.(string); ok {
				args = append(args, "--enable-rule", ruleStr)
			}
		}
	}

	if disableRules, ok := config.CLI["disable_rule"].([]interface{}); ok && len(disableRules) > 0 {
		for _, rule := range disableRules {
			if ruleStr, ok := rule.(string); ok {
				args = append(args, "--disable-rule", ruleStr)
			}
		}
	}

	if rewriteRuleIds, ok := config.CLI["rewrite_rule_ids"].(bool); ok && rewriteRuleIds {
		args = append(args, "--rewrite-rule-ids")
	}

	if noRewriteRuleIds, ok := config.CLI["no_rewrite_rule_ids"].(bool); ok && noRewriteRuleIds {
		args = append(args, "--no-rewrite-rule-ids")
	}

	if validate, ok := config.CLI["validate"].(bool); ok && validate {
		args = append(args, "--validate")
	}

	// Testing features
	if test, ok := config.CLI["test"].(bool); ok && test {
		args = append(args, "--test")
	}

	if testIgnoreTodo, ok := config.CLI["test_ignore_todo"].(bool); ok && testIgnoreTodo {
		args = append(args, "--test-ignore-todo")
	}

	if noTestIgnoreTodo, ok := config.CLI["no_test_ignore_todo"].(bool); ok && noTestIgnoreTodo {
		args = append(args, "--no-test-ignore-todo")
	}

	// Metrics and profiling
	if metrics, ok := config.CLI["metrics"].(string); ok && metrics != "" {
		args = append(args, "--metrics", metrics)
	}

	if time, ok := config.CLI["time"].(bool); ok && time {
		args = append(args, "--time")
	}

	if noTime, ok := config.CLI["no_time"].(bool); ok && noTime {
		args = append(args, "--no-time")
	}

	if profile, ok := config.CLI["profile"].(bool); ok && profile {
		args = append(args, "--profile")
	}

	// Secrets scanning - EXPERIMENTAL
	if secrets, ok := config.CLI["secrets"].(bool); ok && secrets {
		args = append(args, "--secrets")
	}

	if historicalSecrets, ok := config.CLI["historical_secrets"].(bool); ok && historicalSecrets {
		args = append(args, "--historical-secrets")
	}

	if noSecretsValidation, ok := config.CLI["no_secrets_validation"].(bool); ok && noSecretsValidation {
		args = append(args, "--no-secrets-validation")
	}

	// Nosem comments handling
	if enableNosem, ok := config.CLI["enable_nosem"].(bool); ok && enableNosem {
		args = append(args, "--enable-nosem")
	}

	if disableNosem, ok := config.CLI["disable_nosem"].(bool); ok && disableNosem {
		args = append(args, "--disable-nosem")
	}

	// Version checking
	if disableVersionCheck, ok := config.CLI["disable_version_check"].(bool); ok && disableVersionCheck {
		args = append(args, "--disable-version-check")
	}

	if enableVersionCheck, ok := config.CLI["enable_version_check"].(bool); ok && enableVersionCheck {
		args = append(args, "--enable-version-check")
	}

	// Experimental features
	if experimental, ok := config.CLI["experimental"].(bool); ok && experimental {
		args = append(args, "--experimental")
	}

	if allowLocalBuilds, ok := config.CLI["allow_local_builds"].(bool); ok && allowLocalBuilds {
		args = append(args, "--allow-local-builds")
	}

	if allowUntrustedValidators, ok := config.CLI["allow_untrusted_validators"].(bool); ok && allowUntrustedValidators {
		args = append(args, "--allow-untrusted-validators")
	}

	if incrementalOutput, ok := config.CLI["incremental_output"].(bool); ok && incrementalOutput {
		args = append(args, "--incremental-output")
	}

	if optimizations, ok := config.CLI["optimizations"].(string); ok && optimizations != "" {
		args = append(args, "--optimizations", optimizations)
	}

	if ossOnly, ok := config.CLI["oss_only"].(bool); ok && ossOnly {
		args = append(args, "--oss-only")
	}

	if pro, ok := config.CLI["pro"].(bool); ok && pro {
		args = append(args, "--pro")
	}

	if proIntrafile, ok := config.CLI["pro_intrafile"].(bool); ok && proIntrafile {
		args = append(args, "--pro-intrafile")
	}

	if proLanguages, ok := config.CLI["pro_languages"].(bool); ok && proLanguages {
		args = append(args, "--pro-languages")
	}

	if proPathSensitive, ok := config.CLI["pro_path_sensitive"].(bool); ok && proPathSensitive {
		args = append(args, "--pro-path-sensitive")
	}

	if projectRoot, ok := config.CLI["project_root"].(string); ok && projectRoot != "" {
		args = append(args, "--project-root", projectRoot)
	}

	if remote, ok := config.CLI["remote"].(string); ok && remote != "" {
		args = append(args, "--remote", remote)
	}

	if semgrepignoreV2, ok := config.CLI["semgrepignore_v2"].(bool); ok && semgrepignoreV2 {
		args = append(args, "--semgrepignore-v2")
	}

	if showSupportedLanguages, ok := config.CLI["show_supported_languages"].(bool); ok && showSupportedLanguages {
		args = append(args, "--show-supported-languages")
	}

	// Advanced/legacy options
	if legacy, ok := config.CLI["legacy"].(bool); ok && legacy {
		args = append(args, "--legacy")
	}

	if noTrace, ok := config.CLI["no_trace"].(bool); ok && noTrace {
		args = append(args, "--no-trace")
	}

	if trace, ok := config.CLI["trace"].(bool); ok && trace {
		args = append(args, "--trace")
	}

	if traceEndpoint, ok := config.CLI["trace_endpoint"].(string); ok && traceEndpoint != "" {
		args = append(args, "--trace-endpoint", traceEndpoint)
	}

	// Experimental/advanced options (x-* flags)
	if develop, ok := config.CLI["develop"].(bool); ok && develop {
		args = append(args, "--develop")
	}

	if xDisableTransitiveReachability, ok := config.CLI["x_disable_transitive_reachability"].(bool); ok && xDisableTransitiveReachability {
		args = append(args, "--x-disable-transitive-reachability")
	}

	if xDumpSymbolAnalysis, ok := config.CLI["x_dump_symbol_analysis"].(bool); ok && xDumpSymbolAnalysis {
		args = append(args, "--x-dump-symbol-analysis")
	}

	if xEio, ok := config.CLI["x_eio"].(bool); ok && xEio {
		args = append(args, "--x-eio")
	}

	if xGroupTaintRules, ok := config.CLI["x_group_taint_rules"].(bool); ok && xGroupTaintRules {
		args = append(args, "--x-group-taint-rules")
	}

	if xIgnoreSemgrepignoreFiles, ok := config.CLI["x_ignore_semgrepignore_files"].(bool); ok && xIgnoreSemgrepignoreFiles {
		args = append(args, "--x-ignore-semgrepignore-files")
	}

	if xLs, ok := config.CLI["x_ls"].(bool); ok && xLs {
		args = append(args, "--x-ls")
	}

	if xLsLong, ok := config.CLI["x_ls_long"].(bool); ok && xLsLong {
		args = append(args, "--x-ls-long")
	}

	if xMcp, ok := config.CLI["x_mcp"].(bool); ok && xMcp {
		args = append(args, "--x-mcp")
	}

	if xNoPythonSchemaValidation, ok := config.CLI["x_no_python_schema_validation"].(bool); ok && xNoPythonSchemaValidation {
		args = append(args, "--x-no-python-schema-validation")
	}

	if xParmap, ok := config.CLI["x_parmap"].(bool); ok && xParmap {
		args = append(args, "--x-parmap")
	}

	if xProNaming, ok := config.CLI["x_pro_naming"].(bool); ok && xProNaming {
		args = append(args, "--x-pro-naming")
	}

	if xSemgrepignoreFilename, ok := config.CLI["x_semgrepignore_filename"].(string); ok && xSemgrepignoreFilename != "" {
		args = append(args, "--x-semgrepignore-filename", xSemgrepignoreFilename)
	}

	if xSimpleProfiling, ok := config.CLI["x_simple_profiling"].(bool); ok && xSimpleProfiling {
		args = append(args, "--x-simple-profiling")
	}

	if xTr, ok := config.CLI["x_tr"].(bool); ok && xTr {
		args = append(args, "--x-tr")
	}

	if xEnableTransitiveReachability, ok := config.CLI["x_enable_transitive_reachability"].(bool); ok && xEnableTransitiveReachability {
		args = append(args, "--x-enable-transitive-reachability")
	}

	args = append(args, repoPath)
	return args, nil
}

// parseSemgrepFindings parses Semgrep JSON output into findings
func ParseSemgrepFindings(output string) ([]models.Finding, error) {
	var findings []models.Finding

	var semgrepResult struct {
		Results []struct {
			Findings []struct {
				CheckID string `json:"check_id"`
				Path    string `json:"path"`
				Start   struct {
					Line int `json:"line"`
				} `json:"start"`
				Extra struct {
					Message string `json:"message"`
					Code    string `json:"code"`
					Severity string `json:"severity"`
				} `json:"extra"`
			} `json:"results"`
		} `json:"results"`
	}

	if err := json.Unmarshal([]byte(output), &semgrepResult); err != nil {
		return nil, err
	}

	for _, result := range semgrepResult.Results {
		for _, finding := range result.Findings {
			f := models.Finding{
				ID:          fmt.Sprintf("semgrep-%s-%s-%d", finding.CheckID, finding.Path, finding.Start.Line),
				Title:       fmt.Sprintf("Semgrep finding: %s", finding.CheckID),
				Description: finding.Extra.Message,
				Severity:    convertSemgrepSeverity(finding.Extra.Severity),
				File:        finding.Path,
				CodeSnippet: finding.Extra.Code,
				Line:         finding.Start.Line,
				Category:    "code",
				RuleID:      finding.CheckID,
				Tool:        "semgrep",
				Tags:        []string{"semgrep", "code", finding.CheckID},
			}
			findings = append(findings, f)
		}
	}

	return findings, nil
}

// convertSemgrepSeverity converts Semgrep severity to standard format
func convertSemgrepSeverity(severity string) string {
	switch strings.ToUpper(severity) {
	case "ERROR", "HIGH":
		return "high"
	case "WARNING", "MEDIUM":
		return "medium"
	case "INFO", "LOW":
		return "low"
	default:
		return "info"
	}
}

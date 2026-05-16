package runners

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/security-scanner/afss-orchestrator/pkg/models"
)

// buildTrivyArgs builds command line arguments for Trivy
func BuildTrivyArgs(config *models.ToolConfig, repoPath string) ([]string, error) {
	args := []string{}

	// Determine the scan command based on target
	target := "filesystem" // default
	if targetVal, ok := config.CLI["target"].(string); ok && targetVal != "" {
		target = targetVal
	}

	switch target {
	case "filesystem":
		args = append(args, "filesystem")
	case "image":
		args = append(args, "image")
	case "repository":
		args = append(args, "repository")
	case "kubernetes":
		args = append(args, "kubernetes")
	case "sbom":
		args = append(args, "sbom")
	case "vm":
		args = append(args, "vm")
	case "config":
		args = append(args, "config")
	case "rootfs":
		args = append(args, "rootfs")
	default:
		args = append(args, "filesystem")
	}

	// Global flags
	if cacert, ok := config.CLI["cacert"].(string); ok && cacert != "" {
		args = append(args, "--cacert", cacert)
	}

	if cacheDir, ok := config.CLI["cache_dir"].(string); ok && cacheDir != "" {
		args = append(args, "--cache-dir", cacheDir)
	}

	if configFile, ok := config.CLI["config"].(string); ok && configFile != "" {
		args = append(args, "--config", configFile)
	}

	if debug, ok := config.CLI["debug"].(bool); ok && debug {
		args = append(args, "--debug")
	}

	if generateDefaultConfig, ok := config.CLI["generate_default_config"].(bool); ok && generateDefaultConfig {
		args = append(args, "--generate-default-config")
	}

	if insecure, ok := config.CLI["insecure"].(bool); ok && insecure {
		args = append(args, "--insecure")
	}

	if quiet, ok := config.CLI["quiet"].(bool); ok && quiet {
		args = append(args, "--quiet")
	}

	if timeout, ok := config.CLI["timeout"].(string); ok && timeout != "" {
		args = append(args, "--timeout", timeout)
	}

	// Cache flags
	if cacheBackend, ok := config.CLI["cache_backend"].(string); ok && cacheBackend != "" {
		args = append(args, "--cache-backend", cacheBackend)
	}

	if cacheTTL, ok := config.CLI["cache_ttl"].(string); ok && cacheTTL != "" {
		args = append(args, "--cache-ttl", cacheTTL)
	}

	if redisCA, ok := config.CLI["redis_ca"].(string); ok && redisCA != "" {
		args = append(args, "--redis-ca", redisCA)
	}

	if redisCert, ok := config.CLI["redis_cert"].(string); ok && redisCert != "" {
		args = append(args, "--redis-cert", redisCert)
	}

	if redisKey, ok := config.CLI["redis_key"].(string); ok && redisKey != "" {
		args = append(args, "--redis-key", redisKey)
	}

	if redisTLS, ok := config.CLI["redis_tls"].(bool); ok && redisTLS {
		args = append(args, "--redis-tls")
	}

	// DB flags
	if dbRepos, ok := config.CLI["db_repository"].([]interface{}); ok && len(dbRepos) > 0 {
		for _, repo := range dbRepos {
			if repoStr, ok := repo.(string); ok {
				args = append(args, "--db-repository", repoStr)
			}
		}
	}

	if downloadDBOnly, ok := config.CLI["download_db_only"].(bool); ok && downloadDBOnly {
		args = append(args, "--download-db-only")
	}

	if downloadJavaDBOnly, ok := config.CLI["download_java_db_only"].(bool); ok && downloadJavaDBOnly {
		args = append(args, "--download-java-db-only")
	}

	if javaDBRepos, ok := config.CLI["java_db_repository"].([]interface{}); ok && len(javaDBRepos) > 0 {
		for _, repo := range javaDBRepos {
			if repoStr, ok := repo.(string); ok {
				args = append(args, "--java-db-repository", repoStr)
			}
		}
	}

	if noProgress, ok := config.CLI["no_progress"].(bool); ok && noProgress {
		args = append(args, "--no-progress")
	}

	if skipDBUpdate, ok := config.CLI["skip_db_update"].(bool); ok && skipDBUpdate {
		args = append(args, "--skip-db-update")
	}

	if skipJavaDBUpdate, ok := config.CLI["skip_java_db_update"].(bool); ok && skipJavaDBUpdate {
		args = append(args, "--skip-java-db-update")
	}

	// License flags
	if ignoredLicenses, ok := config.CLI["ignored_licenses"].([]interface{}); ok && len(ignoredLicenses) > 0 {
		for _, license := range ignoredLicenses {
			if licenseStr, ok := license.(string); ok {
				args = append(args, "--ignored-licenses", licenseStr)
			}
		}
	}

	if licenseConfidenceLevel, ok := config.CLI["license_confidence_level"].(float64); ok {
		args = append(args, "--license-confidence-level", fmt.Sprintf("%.1f", licenseConfidenceLevel))
	}

	if licenseFull, ok := config.CLI["license_full"].(bool); ok && licenseFull {
		args = append(args, "--license-full")
	}

	// Package flags
	if includeDevDeps, ok := config.CLI["include_dev_deps"].(bool); ok && includeDevDeps {
		args = append(args, "--include-dev-deps")
	}

	if pkgRelationships, ok := config.CLI["pkg_relationships"].([]interface{}); ok && len(pkgRelationships) > 0 {
		relationships := make([]string, len(pkgRelationships))
		for i, rel := range pkgRelationships {
			if relStr, ok := rel.(string); ok {
				relationships[i] = relStr
			}
		}
		if len(relationships) > 0 {
			args = append(args, "--pkg-relationships", strings.Join(relationships, ","))
		}
	}

	if pkgTypes, ok := config.CLI["pkg_types"].([]interface{}); ok && len(pkgTypes) > 0 {
		types := make([]string, len(pkgTypes))
		for i, typ := range pkgTypes {
			if typeStr, ok := typ.(string); ok {
				types[i] = typeStr
			}
		}
		if len(types) > 0 {
			args = append(args, "--pkg-types", strings.Join(types, ","))
		}
	}

	// Report flags
	if compliance, ok := config.CLI["compliance"].(string); ok && compliance != "" {
		args = append(args, "--compliance", compliance)
	}

	if dependencyTree, ok := config.CLI["dependency_tree"].(bool); ok && dependencyTree {
		args = append(args, "--dependency-tree")
	}

	if exitCode, ok := config.CLI["exit_code"].(int); ok && exitCode > 0 {
		args = append(args, "--exit-code", fmt.Sprintf("%d", exitCode))
	}

	if format, ok := config.CLI["format"].(string); ok && format != "" {
		args = append(args, "--format", format)
	}

	if ignoreUnfixed, ok := config.CLI["ignore_unfixed"].(bool); ok && ignoreUnfixed {
		args = append(args, "--ignore-unfixed")
	}

	if scanners, ok := config.CLI["scanners"].([]interface{}); ok && len(scanners) > 0 {
		scannerList := make([]string, len(scanners))
		for i, scanner := range scanners {
			if scannerStr, ok := scanner.(string); ok {
				scannerList[i] = scannerStr
			}
		}
		if len(scannerList) > 0 {
			args = append(args, "--scanners", strings.Join(scannerList, ","))
		}
	}

	if skipVexRepoUpdate, ok := config.CLI["skip_vex_repo_update"].(bool); ok && skipVexRepoUpdate {
		args = append(args, "--skip-vex-repo-update")
	}

	if vexSources, ok := config.CLI["vex"].([]interface{}); ok && len(vexSources) > 0 {
		for _, vex := range vexSources {
			if vexStr, ok := vex.(string); ok {
				args = append(args, "--vex", vexStr)
			}
		}
	}

	if vulnSeveritySources, ok := config.CLI["vuln_severity_source"].([]interface{}); ok && len(vulnSeveritySources) > 0 {
		for _, source := range vulnSeveritySources {
			if sourceStr, ok := source.(string); ok {
				args = append(args, "--vuln-severity-source", sourceStr)
			}
		}
	}

	// Target path
	args = append(args, repoPath)

	return args, nil
}

// parseTrivyFindings parses Trivy JSON output into findings
func ParseTrivyFindings(output string) ([]models.Finding, error) {
	var findings []models.Finding

	// Basic Trivy JSON structure
	var trivyResult struct {
		SchemaVersion int `json:"SchemaVersion"`
		ArtifactName  string `json:"ArtifactName"`
		Results       []struct {
			Target          string `json:"Target"`
			Class           string `json:"Class"`
			Type            string `json:"Type"`
			Vulnerabilities []struct {
				VulnerabilityID  string `json:"VulnerabilityID"`
				PkgName          string `json:"PkgName"`
				InstalledVersion string `json:"InstalledVersion"`
				FixedVersion     string `json:"FixedVersion"`
				Severity         string `json:"Severity"`
				Description      string `json:"Description"`
			} `json:"Vulnerabilities"`
			Misconfigurations []struct {
				Type        string `json:"Type"`
				ID          string `json:"ID"`
				Title       string `json:"Title"`
				Description string `json:"Description"`
				Severity    string `json:"Severity"`
			} `json:"Misconfigurations"`
			Secrets []struct {
				RuleID   string `json:"RuleID"`
				Severity string `json:"Severity"`
				Title    string `json:"Title"`
			} `json:"Secrets"`
		} `json:"Results"`
	}

	if err := json.Unmarshal([]byte(output), &trivyResult); err != nil {
		return nil, err
	}

	for _, result := range trivyResult.Results {
		// Parse vulnerabilities
		for _, vuln := range result.Vulnerabilities {
			finding := models.Finding{
				ID:          fmt.Sprintf("trivy-vuln-%s-%s", vuln.VulnerabilityID, vuln.PkgName),
				Title:       fmt.Sprintf("Vulnerability %s in %s", vuln.VulnerabilityID, vuln.PkgName),
				Description: vuln.Description,
				Severity:    convertTrivySeverity(vuln.Severity),
				File:        result.Target,
				Category:    "vulnerability",
				RuleID:      vuln.VulnerabilityID,
				Tool:        "trivy",
				Tags:        []string{"trivy", "vulnerability", result.Type},
			}
			findings = append(findings, finding)
		}

		// Parse misconfigurations
		for _, misconfig := range result.Misconfigurations {
			finding := models.Finding{
				ID:          fmt.Sprintf("trivy-misconfig-%s", misconfig.ID),
				Title:       misconfig.Title,
				Description: misconfig.Description,
				Severity:    convertTrivySeverity(misconfig.Severity),
				File:        result.Target,
				Category:    "misconfiguration",
				RuleID:      misconfig.ID,
				Tool:        "trivy",
				Tags:        []string{"trivy", "misconfiguration", misconfig.Type},
			}
			findings = append(findings, finding)
		}

		// Parse secrets
		for _, secret := range result.Secrets {
			finding := models.Finding{
				ID:          fmt.Sprintf("trivy-secret-%s", secret.RuleID),
				Title:       secret.Title,
				Description: "Secret found",
				Severity:    convertTrivySeverity(secret.Severity),
				File:        result.Target,
				Category:    "secret",
				RuleID:      secret.RuleID,
				Tool:        "trivy",
				Tags:        []string{"trivy", "secret"},
			}
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// convertTrivySeverity converts Trivy severity to standard format
func convertTrivySeverity(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	case "UNKNOWN":
		return "info"
	default:
		return "info"
	}
}
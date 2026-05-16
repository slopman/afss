package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/security-scanner/afss-orchestrator/pkg/config"
	"github.com/security-scanner/afss-orchestrator/pkg/executor"
	"github.com/security-scanner/afss-orchestrator/pkg/findings_processor"
	"github.com/security-scanner/afss-orchestrator/pkg/models"
	"github.com/security-scanner/afss-orchestrator/pkg/monitor"
	"github.com/security-scanner/afss-orchestrator/pkg/normalizers"
	"github.com/security-scanner/afss-orchestrator/pkg/tools"
	"github.com/security-scanner/afss-orchestrator/pkg/util"
)

func main() {
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "scan":
		if len(os.Args) < 3 {
			fmt.Println("Usage: orchestrator scan <repo-path>")
			os.Exit(1)
		}
		repoPath := os.Args[2]
		runScan(repoPath, logger)

	case "profile":
		if len(os.Args) < 4 {
			fmt.Println("Usage: orchestrator profile <tool-name> <repo-path>")
			os.Exit(1)
		}
		toolName := os.Args[2]
		repoPath := os.Args[3]
		runProfile(toolName, repoPath, logger)

	case "monitor":
		runMonitor(logger)

	case "config":
		if len(os.Args) < 3 {
			fmt.Println("Usage: orchestrator config <init|validate>")
			os.Exit(1)
		}
		action := os.Args[2]
		handleConfig(action, logger)

	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("AFSS Orchestrator v1.0")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("  orchestrator scan <repo-path>      - Run full security scan")
	fmt.Println("  orchestrator profile <tool> <repo> - Profile tool resource usage")
	fmt.Println("  orchestrator monitor               - Show system resource monitoring")
	fmt.Println("  orchestrator config <init|validate> - Manage configurations")
	fmt.Println("")
	fmt.Println("Examples:")
	fmt.Println("  orchestrator scan /path/to/project")
	fmt.Println("  orchestrator profile gosec /path/to/go-project")
	fmt.Println("  orchestrator monitor")
	fmt.Println("  orchestrator config init")
}

// runScan performs a full security scan
func runScan(repoPath string, logger *logrus.Logger) {
	logger.WithField("repo", repoPath).Info("Starting AFSS scan")

	// Check if repo exists
	if _, err := os.Stat(repoPath); os.IsNotExist(err) {
		logger.Fatalf("Repository path does not exist: %s", repoPath)
	}

	// Initialize resource monitor
	resourceMonitor := monitor.NewResourceMonitor(logger)

	// Get system info
	systemInfo := resourceMonitor.GetSystemInfo()
	logger.WithFields(logrus.Fields{
		"memory_mb": systemInfo.TotalMemoryMB,
		"cpu_cores": systemInfo.CPUCount,
		"disk_mb":   systemInfo.TotalDiskMB,
	}).Info("System resources detected")

	// Initialize config manager
	configDir := getConfigDir()
	configManager := config.NewManager(configDir, logger)

	// Load orchestrator config
	orchConfig, err := configManager.LoadOrchestratorConfig(filepath.Join(configDir, "orchestrator.yaml"))
	if err != nil {
		logger.Fatalf("Failed to load orchestrator config: %v", err)
	}

	// Load tool configs
	toolConfigs, err := configManager.LoadAllToolConfigs()
	if err != nil {
		logger.Fatalf("Failed to load tool configs: %v", err)
	}

	logger.WithFields(logrus.Fields{
		"orchestrator_version": orchConfig.Version,
		"tools_enabled":        len(toolConfigs),
	}).Info("Configuration loaded")

	scanTimeout := time.Duration(orchConfig.Global.TimeoutSeconds) * time.Second
	if scanTimeout <= 0 {
		scanTimeout = 30 * time.Minute
	}

	// Start monitoring (same lifetime as scan)
	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()

	logger.WithField("scan_timeout", scanTimeout.String()).Info("Scan context created")

	resourceMonitor.StartMonitoring(ctx, 5*time.Second)
	defer resourceMonitor.StopMonitoring()

	// Initialize executor components
	resourceManager := executor.NewResourceManager(resourceMonitor, orchConfig)
	adaptiveExecutor := executor.NewAdaptiveExecutor(resourceManager, logger)
	toolRunner := tools.NewRunner(logger, adaptiveExecutor)

	// Register tool profiles
	for _, config := range toolConfigs {
		resourceManager.RegisterToolProfile(config.ResourceProfile)
	}

	// --- NEW: Pre-flight Check ---
	fmt.Printf("\n🔍 Pre-flight check: validating tools...\n")
	validationResults := toolRunner.ValidateTools(toolConfigs)
	readyCount := 0
	for name, ready := range validationResults {
		if ready {
			fmt.Printf("  ✅ %s: Ready\n", name)
			readyCount++
		} else {
			fmt.Printf("  ❌ %s: Not found (will be skipped)\n", name)
			// Disable tool if not found
			if cfg, ok := toolConfigs[name]; ok {
				cfg.Enabled = false
			}
		}
	}

	if readyCount == 0 {
		fmt.Printf("\n❌ No tools are ready for execution. Please check your tools/ directory or PATH.\n")
		return
	}

	scheduledToolNames := make([]string, 0, len(toolConfigs))
	for name, cfg := range toolConfigs {
		if cfg.Enabled {
			scheduledToolNames = append(scheduledToolNames, name)
		}
	}
	sort.Strings(scheduledToolNames)

	// Results collection
	var results []models.ToolResult
	var mu sync.Mutex
	completedCount := 0
	totalTools := readyCount

	// Run tools
	var wg sync.WaitGroup
	for toolName, config := range toolConfigs {
		if !config.Enabled {
			continue
		}
		wg.Add(1)
		go func(name string, cfg *models.ToolConfig) {
			defer wg.Done()
			res, err := toolRunner.RunTool(ctx, cfg, repoPath)
			
			mu.Lock()
			completedCount++
			fmt.Printf("\r⏳ Progress: [%d/%d] tools completed...", completedCount, totalTools)
			if err != nil {
				logger.Errorf("Tool %s failed: %v", name, err)
			} else {
				results = append(results, *res)
			}
			mu.Unlock()
		}(toolName, config)
	}

	wg.Wait()
	fmt.Printf("\n✅ Tool execution phase completed\n")

	// --- NEW: Final Processing Phase ---
	
	logger.Info("Starting findings processing phase")
	
	// 1. Gather all raw findings and normalize them properly
	normalizerFactory := normalizers.NewNormalizerFactory()
	var allNormalized []findings_processor.NormalizedFinding
	
	for _, res := range results {
		output := strings.TrimSpace(res.Output)
		if output == "" {
			logger.Debugf("Tool %s returned empty output, skipping normalization", res.ToolName)
			continue
		}

		// Try to find where JSON starts (ignoring potential CLI warnings/headers)
		jsonStart := -1
		for i, char := range output {
			if char == '{' || char == '[' {
				// Verify if it's likely a JSON by looking for quotes or closing brackets (basic check)
				trimmedRest := strings.TrimSpace(output[i:])
				if len(trimmedRest) > 1 {
					jsonStart = i
					break
				}
			}
		}

		payload := output
		if jsonStart == -1 {
			if res.ToolName != "hadolint" {
				logger.Warnf("Tool %s output does not look like JSON, skipping normalization (Output: %.50s...)", res.ToolName, output)
				continue
			}
			// Hadolint may print parse errors or tty format without leading '[' / '{'.
		} else {
			cleanJSON := output[jsonStart:]
			if res.ToolName != "govulncheck" {
				var trimmed string
				if res.ToolName == "trivy" {
					trimmed = util.FirstJSONObjectWithKey(cleanJSON, "Results")
				}
				if trimmed == "" {
					trimmed = util.FirstJSONValue(cleanJSON)
				}
				if trimmed != "" {
					cleanJSON = trimmed
				}
			}
			payload = cleanJSON
		}

		normalizer := normalizerFactory.GetNormalizerByTool(res.ToolName)
		if normalizer == nil {
			logger.Warnf("No advanced normalizer for %s, skipping advanced processing", res.ToolName)
			continue
		}

		findings, err := normalizer.Normalize([]byte(payload))
		if err != nil {
			logger.Errorf("Failed to normalize results from %s: %v", res.ToolName, err)
			continue
		}
		allNormalized = append(allNormalized, findings...)
	}
	
	// 2. Process findings (Deduplication, Correlation, Filtering)
	processorConfig := findings_processor.DefaultConfig()
	processor := findings_processor.NewFindingsProcessor(processorConfig)
	
	finalFindings, correlations, err := processor.ProcessNormalized(allNormalized)
	if err != nil {
		logger.Errorf("Final processing failed: %v", err)
	} else {
		// 3. Save findings and summary
		os.MkdirAll("results", 0755)
		saveFinalReport(finalFindings, correlations, logger)
		
		// 4. Generate HTML Report
		generateHTMLReport(finalFindings, correlations, scheduledToolNames, logger)
	}

	logger.Info("AFSS scan completed")
}

func saveFinalReport(findings []findings_processor.NormalizedFinding, correlations []findings_processor.Correlation, logger *logrus.Logger) {
	report := struct {
		Timestamp    time.Time                             `json:"timestamp"`
		ToolCount    int                                   `json:"tool_count"`
		FindingCount int                                   `json:"finding_count"`
		Findings     []findings_processor.NormalizedFinding `json:"findings"`
		Correlations []findings_processor.Correlation      `json:"correlations"`
	}{
		Timestamp:    time.Now(),
		FindingCount: len(findings),
		Findings:     findings,
		Correlations: correlations,
	}

	data, _ := json.MarshalIndent(report, "", "  ")
	err := os.WriteFile("results/actionable_findings.json", data, 0644)
	if err != nil {
		logger.Errorf("Failed to save final report: %v", err)
	} else {
		fmt.Printf("\n✨ Actionable findings saved to results/actionable_findings.json\n")
		fmt.Printf("📊 Final report: %d findings, %d correlations\n", len(findings), len(correlations))
	}
}

// runProfile profiles resource usage of a specific tool
func runProfile(toolName, repoPath string, logger *logrus.Logger) {
	logger.WithFields(logrus.Fields{"tool": toolName, "repo": repoPath}).Info("Starting tool profiling")

	// Initialize resource monitor
	resourceMonitor := monitor.NewResourceMonitor(logger)

	// Start monitoring
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	resourceMonitor.StartMonitoring(ctx, 1*time.Second)
	defer resourceMonitor.StopMonitoring()

	logger.Info("Resource monitoring started")

	// TODO: Implement actual tool execution and profiling
	fmt.Printf("\n🔬 Tool Profiling Mode\n")
	fmt.Printf("Tool: %s\n", toolName)
	fmt.Printf("Repository: %s\n", repoPath)
	fmt.Printf("Monitoring: active\n")

	fmt.Printf("\n⚠️  Tool profiling not yet implemented\n")
	fmt.Printf("This will measure actual resource consumption of tools.\n")
}

// runMonitor shows system resource monitoring
func runMonitor(logger *logrus.Logger) {
	resourceMonitor := monitor.NewResourceMonitor(logger)

	systemInfo := resourceMonitor.GetSystemInfo()

	fmt.Printf("🖥️  System Resource Monitor\n")
	fmt.Printf("Total Memory: %d MB\n", systemInfo.TotalMemoryMB)
	fmt.Printf("CPU Cores: %d\n", systemInfo.CPUCount)
	fmt.Printf("Total Disk: %d MB\n", systemInfo.TotalDiskMB)

	// Start monitoring for 10 seconds
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resourceMonitor.StartMonitoring(ctx, 2*time.Second)

	fmt.Printf("\nMonitoring for 10 seconds...\n")
	fmt.Printf("Time\t\tMemory%%\tCPU%%\tMemory MB\n")

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	startTime := time.Now()
	for {
		select {
		case <-ctx.Done():
			fmt.Printf("\nMonitoring completed.\n")
			return
		case <-ticker.C:
			snapshot := resourceMonitor.GetCurrentResources()
			elapsed := time.Since(startTime).Round(time.Second)

			fmt.Printf("%s\t%.1f%%\t\t%.1f%%\t%d MB\n",
				elapsed,
				snapshot.MemoryPercent,
				snapshot.CPUUsedPercent,
				snapshot.MemoryUsedMB)
		}
	}
}

// handleConfig manages configuration files
func handleConfig(action string, logger *logrus.Logger) {
	configDir := getConfigDir()
	configManager := config.NewManager(configDir, logger)

	switch action {
	case "init":
		logger.Info("Creating default configurations")

		if err := configManager.CreateDefaultConfigs(); err != nil {
			logger.Fatalf("Failed to create default configs: %v", err)
		}

		fmt.Printf("✅ Default configurations created in %s\n", configDir)

	case "validate":
		logger.Info("Validating configurations")

		// Validate orchestrator config
		orchConfig, err := configManager.LoadOrchestratorConfig(filepath.Join(configDir, "orchestrator.yaml"))
		if err != nil {
			logger.Fatalf("Invalid orchestrator config: %v", err)
		}

		// Validate tool configs
		toolConfigs, err := configManager.LoadAllToolConfigs()
		if err != nil {
			logger.Fatalf("Failed to load tool configs: %v", err)
		}

		fmt.Printf("✅ Configuration validation passed\n")
		fmt.Printf("Orchestrator version: %s\n", orchConfig.Version)
		fmt.Printf("Tools validated: %d\n", len(toolConfigs))

	default:
		fmt.Printf("Unknown config action: %s\n", action)
		fmt.Println("Available actions: init, validate")
		os.Exit(1)
	}
}

// getConfigDir returns the configuration directory path
func getConfigDir() string {
	// Check for --config-dir flag
	for i, arg := range os.Args {
		if arg == "--config-dir" && i+1 < len(os.Args) {
			return os.Args[i+1]
		}
	}

	// Default to ./configs
	if _, err := os.Stat("./configs"); err == nil {
		return "./configs"
	}

	// Try home directory
	homeDir, err := os.UserHomeDir()
	if err == nil {
		return filepath.Join(homeDir, ".afss", "configs")
	}

	// Fallback to current directory
	return "./configs"
}
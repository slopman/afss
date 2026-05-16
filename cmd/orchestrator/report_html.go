package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/security-scanner/afss-orchestrator/pkg/findings_processor"
)

const reportTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AFSS Security Audit Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --bg-color: #0d1117;
            --text-color: #c9d1d9;
            --sidebar-color: #161b22;
            --accent-color: #58a6ff;
            --critical: #f85149;
            --high: #d29922;
            --medium: #bc8cff;
            --low: #3fb950;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            display: flex;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 40px;
            width: 100%;
        }
        h1, h2, h3 { color: #ffffff; }
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }
        .card {
            background-color: var(--sidebar-color);
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border: 1px solid #30363d;
        }
        .card .value {
            font-size: 2.5em;
            font-weight: bold;
            display: block;
        }
        .card .label { color: #8b949e; }
        
        .charts-row {
            display: flex; gap: 40px; margin-bottom: 40px; flex-wrap: wrap;
        }
        .chart-container {
            flex: 1; min-width: 300px; background: var(--sidebar-color); padding: 20px;
            border-radius: 8px; border: 1px solid #30363d;
        }

        table {
            width: 100%; border-collapse: collapse; background: var(--sidebar-color);
            border-radius: 8px; overflow: hidden; border: 1px solid #30363d;
        }
        th, td { text-align: left; padding: 12px 15px; border-bottom: 1px solid #30363d; }
        th { background-color: #1f242c; color: #8b949e; }
        tr:hover { background-color: #1c2128; }

        .severity-badge {
            padding: 2px 8px; border-radius: 12px; font-size: 0.8em; font-weight: bold; text-transform: uppercase;
        }
        .sev-critical { background: rgba(248, 81, 73, 0.2); color: var(--critical); border: 1px solid var(--critical); }
        .sev-high { background: rgba(210, 153, 34, 0.2); color: var(--high); border: 1px solid var(--high); }
        .sev-medium { background: rgba(188, 140, 255, 0.2); color: var(--medium); border: 1px solid var(--medium); }
        .sev-low { background: rgba(63, 185, 80, 0.2); color: var(--low); border: 1px solid var(--low); }

        .tag { background: #21262d; border: 1px solid #30363d; padding: 1px 6px; border-radius: 4px; font-size: 0.75em; margin-right: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Security Audit Report</h1>
        <p style="color: #8b949e;">Generated on {{.GeneratedAt}}</p>

        <div class="summary-cards">
            <div class="card">
                <span class="value">{{len .Findings}}</span>
                <span class="label">Total Findings</span>
            </div>
            <div class="card">
                <span class="value">{{len .Correlations}}</span>
                <span class="label">Correlations</span>
            </div>
            <div class="card">
                <span class="value">{{.CriticalCount}}</span>
                <span class="label" style="color: var(--critical);">Critical</span>
            </div>
            <div class="card">
                <span class="value">{{.HighCount}}</span>
                <span class="label" style="color: var(--high);">High</span>
            </div>
        </div>

        <h2>Findings by tool (this run)</h2>
        <p style="color: #8b949e;">All tools that were scheduled for the scan. Count is after dedup/filter in the pipeline — zero means no actionable finding rows for that tool.</p>
        <div style="overflow-x: auto; margin-bottom: 32px;">
            <table>
                <thead>
                    <tr>
                        <th>Tool</th>
                        <th>Count in report</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .ToolRows}}
                    <tr>
                        <td><span class="tag">{{.Name}}</span></td>
                        <td>{{.Count}}</td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>

        <div class="charts-row">
            <div class="chart-container">
                <h3>Severity Distribution</h3>
                <canvas id="severityChart"></canvas>
            </div>
            <div class="chart-container">
                <h3>Findings by Tool</h3>
                <canvas id="toolChart"></canvas>
            </div>
        </div>

        <h2>Detailed Findings</h2>
        <div style="overflow-x: auto;">
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Tool</th>
                        <th>Finding</th>
                        <th>File</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Findings}}
                    <tr>
                        <td><span class="severity-badge sev-{{.Severity | lower}}">{{.Severity}}</span></td>
                        <td>{{.Tool}}</td>
                        <td>
                            <strong>{{.Title}}</strong><br>
                            <span style="font-size: 0.85em; color: #8b949e;">{{.RuleID}}</span>
                        </td>
                        <td>
                            <code>{{.File}}:{{.Line}}</code>
                        </td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>
    </div>

    <script>
        // Severity Chart
        new Chart(document.getElementById('severityChart'), {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{
                    data: [{{.CriticalCount}}, {{.HighCount}}, {{.MediumCount}}, {{.LowCount}}, {{.InfoCount}}],
                    backgroundColor: ['#f85149', '#d29922', '#bc8cff', '#3fb950', '#8b949e'],
                    borderWidth: 0
                }]
            },
            options: { plugins: { legend: { position: 'bottom', labels: { color: '#c9d1d9' } } } }
        });

        // Tool Chart (labels/data from one sorted pass — map range order is undefined in Go)
        new Chart(document.getElementById('toolChart'), {
            type: 'bar',
            data: {
                labels: {{.ToolChartLabelsJSON}},
                datasets: [{
                    label: 'Findings',
                    data: {{.ToolChartDataJSON}},
                    backgroundColor: '#58a6ff'
                }]
            },
            options: { 
                scales: { 
                    y: { beginAtZero: true, grid: { color: '#30363d' }, ticks: { color: '#8b949e' } },
                    x: { grid: { display: false }, ticks: { color: '#8b949e' } }
                },
                plugins: { legend: { display: false } }
            }
        });
    </script>
</body>
</html>
`

type ToolRow struct {
	Name  string
	Count int
}

type ReportData struct {
	GeneratedAt   string
	Findings      []findings_processor.NormalizedFinding
	Correlations []findings_processor.Correlation
	CriticalCount int
	HighCount     int
	MediumCount   int
	LowCount      int
	InfoCount     int
	ToolBreakdown map[string]int
	/** JSON arrays for Chart.js — safe embedding via template.JS */
	ToolChartLabelsJSON template.JS
	ToolChartDataJSON   template.JS
	ToolRows            []ToolRow
}

func generateHTMLReport(findings []findings_processor.NormalizedFinding, correlations []findings_processor.Correlation, scheduledTools []string, logger *logrus.Logger) {
	data := ReportData{
		GeneratedAt:   time.Now().Format("2006-01-02 15:04:05"),
		Findings:      findings,
		Correlations: correlations,
		ToolBreakdown: make(map[string]int),
	}

	for _, t := range scheduledTools {
		data.ToolBreakdown[t] = 0
	}

	for _, f := range findings {
		switch f.Severity {
		case findings_processor.Critical:
			data.CriticalCount++
		case findings_processor.High:
			data.HighCount++
		case findings_processor.Medium:
			data.MediumCount++
		case findings_processor.Low:
			data.LowCount++
		case findings_processor.Info:
			data.InfoCount++
		}
		data.ToolBreakdown[f.Tool]++
	}

	chartKeys := make([]string, 0, len(data.ToolBreakdown))
	for k := range data.ToolBreakdown {
		chartKeys = append(chartKeys, k)
	}
	sort.Strings(chartKeys)
	chartVals := make([]int, len(chartKeys))
	for i, k := range chartKeys {
		chartVals[i] = data.ToolBreakdown[k]
	}
	labelsJSON, err := json.Marshal(chartKeys)
	if err != nil {
		logger.Errorf("tool chart labels json: %v", err)
		labelsJSON = []byte("[]")
	}
	dataJSON, err := json.Marshal(chartVals)
	if err != nil {
		logger.Errorf("tool chart data json: %v", err)
		dataJSON = []byte("[]")
	}
	data.ToolChartLabelsJSON = template.JS(labelsJSON)
	data.ToolChartDataJSON = template.JS(dataJSON)

	toolRows := make([]ToolRow, len(chartKeys))
	for i, k := range chartKeys {
		toolRows[i] = ToolRow{Name: k, Count: chartVals[i]}
	}
	data.ToolRows = toolRows

	funcMap := template.FuncMap{
		"lower": func(s findings_processor.SeverityLevel) string {
			return strings.ToLower(string(s))
		},
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(reportTemplate)
	if err != nil {
		logger.Errorf("Failed to parse HTML template: %v", err)
		return
	}

	reportPath := filepath.Join("results", "report.html")
	file, err := os.Create(reportPath)
	if err != nil {
		logger.Errorf("Failed to create report file: %v", err)
		return
	}
	defer file.Close()

	if err := tmpl.Execute(file, data); err != nil {
		logger.Errorf("Failed to execute template: %v", err)
		return
	}

	fmt.Printf("\n📊 HTML report generated: %s\n", reportPath)
}

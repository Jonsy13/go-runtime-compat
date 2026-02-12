// Package report provides report generation capabilities for go-runtime-compat.
package report

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/Jonsy13/go-runtime-compat/internal/rules"
)

// sourceLineCache caches source lines to avoid re-reading files
var sourceLineCache = make(map[string][]string)

// Reporter generates reports from analysis results.
type Reporter struct {
	format string
}

// NewReporter creates a new reporter with the specified output format.
func NewReporter(format string) *Reporter {
	return &Reporter{
		format: format,
	}
}

// Generate generates a report from the analysis result.
func (r *Reporter) Generate(result *rules.Result) (string, error) {
	switch r.format {
	case "json":
		return r.generateJSON(result)
	case "csv":
		return r.generateCSV(result)
	case "cli":
		return r.generateCLI(result)
	default:
		return r.generateCLI(result)
	}
}

// generateJSON generates a JSON report.
func (r *Reporter) generateJSON(result *rules.Result) (string, error) {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal result to JSON: %w", err)
	}
	return string(data), nil
}

// generateCLI generates a CLI-friendly report.
func (r *Reporter) generateCLI(result *rules.Result) (string, error) {
	var sb strings.Builder

	// Header
	sb.WriteString("\n")
	sb.WriteString("╔══════════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║              go-runtime-compat Analysis Report                   ║\n")
	sb.WriteString("╚══════════════════════════════════════════════════════════════════╝\n")
	sb.WriteString("\n")

	// Summary
	sb.WriteString("📊 Summary\n")
	sb.WriteString("──────────────────────────────────────────────────────────────────\n")
	sb.WriteString(fmt.Sprintf("  Total Findings: %d\n", result.Summary.TotalFindings))
	sb.WriteString(fmt.Sprintf("  ❌ Errors:      %d\n", result.Summary.ErrorCount))
	sb.WriteString(fmt.Sprintf("  ⚠️  Warnings:    %d\n", result.Summary.WarningCount))
	sb.WriteString(fmt.Sprintf("  ℹ️  Info:        %d\n", result.Summary.InfoCount))
	sb.WriteString("\n")

	// Status
	if result.Passed {
		sb.WriteString("✅ Status: PASSED\n")
	} else {
		sb.WriteString("❌ Status: FAILED\n")
	}
	sb.WriteString("\n")

	// Findings by category
	if len(result.Findings) > 0 {
		sb.WriteString("📋 Findings by Category\n")
		sb.WriteString("──────────────────────────────────────────────────────────────────\n")

		// Group findings by category
		byCategory := make(map[rules.Category][]rules.Finding)
		for _, f := range result.Findings {
			byCategory[f.Category] = append(byCategory[f.Category], f)
		}

		// Sort categories
		categories := make([]rules.Category, 0, len(byCategory))
		for cat := range byCategory {
			categories = append(categories, cat)
		}
		sort.Slice(categories, func(i, j int) bool {
			return string(categories[i]) < string(categories[j])
		})

		for _, cat := range categories {
			findings := byCategory[cat]
			sb.WriteString(fmt.Sprintf("\n  📁 %s (%d findings)\n", formatCategory(cat), len(findings)))
			sb.WriteString("  ────────────────────────────────────────────────────────────\n")

			for _, f := range findings {
				icon := getSeverityIcon(f.Severity)
				sb.WriteString(fmt.Sprintf("  %s [%s] %s\n", icon, f.RuleID, f.Message))

				// Show command/binary details if available
				if f.Details != nil {
					if cmd, ok := f.Details["command"].(string); ok && cmd != "" {
						sb.WriteString(fmt.Sprintf("     🔧 Command: %s\n", cmd))
						if args, ok := f.Details["args"].([]string); ok && len(args) > 0 {
							sb.WriteString(fmt.Sprintf("     📝 Args: %s\n", strings.Join(args, " ")))
						}
					}
					if lib, ok := f.Details["library"].(string); ok && lib != "" {
						sb.WriteString(fmt.Sprintf("     📦 Library: %s\n", lib))
					}
					// Show package details for import/dependency findings
					if pkg, ok := f.Details["package"].(string); ok && pkg != "" {
						sb.WriteString(fmt.Sprintf("     📦 Package: %s\n", pkg))
					}
					if cgoFiles, ok := f.Details["cgo_files"].([]string); ok && len(cgoFiles) > 0 {
						sb.WriteString(fmt.Sprintf("     🔗 CGO Files: %s\n", strings.Join(cgoFiles, ", ")))
					}
					if cFiles, ok := f.Details["c_files"].([]string); ok && len(cFiles) > 0 {
						sb.WriteString(fmt.Sprintf("     🔗 C Files: %s\n", strings.Join(cFiles, ", ")))
					}
				}

				if f.Location.File != "" {
					location := f.Location.File
					if f.Location.Line > 0 {
						location = fmt.Sprintf("%s:%d", location, f.Location.Line)
					}
					if f.Location.Stage != "" {
						location = fmt.Sprintf("%s (stage: %s)", location, f.Location.Stage)
					}
					sb.WriteString(fmt.Sprintf("     📍 Location: %s\n", location))

					// Show the actual source line
					if f.Location.Line > 0 {
						sourceLine := getSourceLine(f.Location.File, f.Location.Line)
						if sourceLine != "" {
							sb.WriteString(fmt.Sprintf("     📄 Code: %s\n", sourceLine))
						}
					}
				}

				if f.Suggestion != "" {
					sb.WriteString(fmt.Sprintf("     💡 Suggestion: %s\n", f.Suggestion))
				}
				sb.WriteString("\n")
			}
		}
	} else {
		sb.WriteString("✨ No compatibility issues found!\n")
	}

	sb.WriteString("──────────────────────────────────────────────────────────────────\n")

	return sb.String(), nil
}

// formatCategory formats a category name for display.
func formatCategory(cat rules.Category) string {
	switch cat {
	case rules.CategoryExecCommand:
		return "Exec Command"
	case rules.CategoryCGO:
		return "CGO"
	case rules.CategoryDynamicLinking:
		return "Dynamic Linking"
	case rules.CategoryDockerfile:
		return "Dockerfile"
	case rules.CategoryBaseImage:
		return "Base Image"
	case rules.CategoryMultiStage:
		return "Multi-Stage Build"
	default:
		return string(cat)
	}
}

// getSeverityIcon returns an icon for the severity level.
func getSeverityIcon(severity rules.Severity) string {
	switch severity {
	case rules.SeverityError:
		return "❌"
	case rules.SeverityWarning:
		return "⚠️ "
	case rules.SeverityInfo:
		return "ℹ️ "
	default:
		return "•"
	}
}

// generateCSV generates a CSV report.
func (r *Reporter) generateCSV(result *rules.Result) (string, error) {
	var sb strings.Builder
	writer := csv.NewWriter(&sb)

	// Write header
	header := []string{
		"Rule ID",
		"Category",
		"Severity",
		"Message",
		"File",
		"Line",
		"Command/Binary",
		"Arguments",
		"Suggestion",
	}
	if err := writer.Write(header); err != nil {
		return "", fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Write findings
	for _, f := range result.Findings {
		// Extract command/binary from details
		command := ""
		args := ""
		if f.Details != nil {
			if cmd, ok := f.Details["command"].(string); ok {
				command = cmd
			}
			if binary, ok := f.Details["binary"].(string); ok && command == "" {
				command = binary
			}
			if argList, ok := f.Details["args"].([]string); ok {
				args = strings.Join(argList, " ")
			}
		}

		row := []string{
			f.RuleID,
			string(f.Category),
			string(f.Severity),
			f.Message,
			f.Location.File,
			fmt.Sprintf("%d", f.Location.Line),
			command,
			args,
			f.Suggestion,
		}
		if err := writer.Write(row); err != nil {
			return "", fmt.Errorf("failed to write CSV row: %w", err)
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return "", fmt.Errorf("failed to flush CSV writer: %w", err)
	}

	return sb.String(), nil
}

// getSourceLine reads a specific line from a file.
func getSourceLine(filePath string, lineNum int) string {
	if lineNum <= 0 {
		return ""
	}

	// Check cache first
	if lines, ok := sourceLineCache[filePath]; ok {
		if lineNum <= len(lines) {
			return strings.TrimSpace(lines[lineNum-1])
		}
		return ""
	}

	// Read file and cache lines
	file, err := os.Open(filePath)
	if err != nil {
		return ""
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	// Cache the lines
	sourceLineCache[filePath] = lines

	if lineNum <= len(lines) {
		return strings.TrimSpace(lines[lineNum-1])
	}
	return ""
}

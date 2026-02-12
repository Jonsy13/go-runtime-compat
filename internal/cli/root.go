// Package cli provides the command-line interface for go-runtime-compat.
package cli

import (
	"encoding/json"
	"fmt"

	"github.com/Jonsy13/go-runtime-compat/internal/analyzer"
	"github.com/Jonsy13/go-runtime-compat/internal/correlator"
	"github.com/Jonsy13/go-runtime-compat/internal/docker"
	"github.com/Jonsy13/go-runtime-compat/internal/report"
	"github.com/Jonsy13/go-runtime-compat/internal/rules"
	"github.com/spf13/cobra"
)

var (
	outputFormat   string
	dockerfilePath string
	imageName      string
	projectPath    string
	strictMode     bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "go-runtime-compat",
	Short: "Detect container compatibility issues in Go projects",
	Long: `go-runtime-compat is a static analyzer that detects container compatibility
issues in Go projects.

It analyzes:
  - Go source code for exec.Command usage and CGO dependencies
  - Dockerfiles for multi-stage builds and base image compatibility
  - Docker images for dynamic linking issues

Examples:
  # Analyze a Go project
  go-runtime-compat analyze --project ./myapp

  # Analyze a Dockerfile
  go-runtime-compat analyze --dockerfile ./Dockerfile

  # Analyze a Docker image
  go-runtime-compat analyze --image myapp:latest

  # Full analysis with JSON output
  go-runtime-compat analyze --project ./myapp --dockerfile ./Dockerfile --image myapp:latest --output json`,
	RunE: runAnalyze,
}

// analyzeCmd represents the analyze command
var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Analyze project for container compatibility issues",
	Long: `Analyze a Go project, Dockerfile, or Docker image for container compatibility issues.

The analyzer checks for:
  - exec.Command usage that may not work in containers
  - CGO dependencies that require specific libraries
  - Dynamic linking issues detected via ldd
  - Dockerfile best practices and multi-stage build issues
  - Base image compatibility`,
	RunE: runAnalyze,
}

func init() {
	rootCmd.AddCommand(analyzeCmd)

	// Add flags to both root and analyze commands
	for _, cmd := range []*cobra.Command{rootCmd, analyzeCmd} {
		cmd.Flags().StringVarP(&outputFormat, "output", "o", "cli", "Output format: cli, json, csv")
		cmd.Flags().StringVarP(&dockerfilePath, "dockerfile", "d", "", "Path to Dockerfile")
		cmd.Flags().StringVarP(&imageName, "image", "i", "", "Docker image name to analyze")
		cmd.Flags().StringVarP(&projectPath, "project", "p", "", "Path to Go project")
		cmd.Flags().BoolVarP(&strictMode, "strict", "s", false, "Strict mode: fail on warnings")
	}
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return rootCmd.Execute()
}

func runAnalyze(cmd *cobra.Command, args []string) error {
	if projectPath == "" && dockerfilePath == "" && imageName == "" {
		return fmt.Errorf("at least one of --project, --dockerfile, or --image must be specified")
	}

	// Initialize the rules engine
	engine := rules.NewEngine()

	// Collect findings by source for correlation
	var goFindings []rules.Finding
	var dockerfileFindings []rules.Finding
	var imageFindings []rules.Finding

	// Analyze Go project
	if projectPath != "" {
		goAnalyzer := analyzer.NewGoAnalyzer()
		findings, err := goAnalyzer.Analyze(projectPath)
		if err != nil {
			return fmt.Errorf("failed to analyze Go project: %w", err)
		}
		goFindings = findings

		// Add binary summary (all unique binaries detected)
		binarySummary := goAnalyzer.GetBinarySummary()
		goFindings = append(goFindings, binarySummary...)

		// Analyze dependencies for CGO usage
		depFindings, err := goAnalyzer.AnalyzeDependencies(projectPath)
		if err != nil {
			// Don't fail on dependency analysis errors, just skip
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: could not analyze dependencies: %v\n", err)
		} else {
			goFindings = append(goFindings, depFindings...)
		}
	}

	// Analyze Dockerfile
	if dockerfilePath != "" {
		dockerfileAnalyzer := docker.NewDockerfileAnalyzer()
		findings, err := dockerfileAnalyzer.Analyze(dockerfilePath)
		if err != nil {
			return fmt.Errorf("failed to analyze Dockerfile: %w", err)
		}
		dockerfileFindings = findings
	}

	// Analyze Docker image
	if imageName != "" {
		imageInspector := docker.NewImageInspector()
		findings, err := imageInspector.Analyze(imageName)
		if err != nil {
			return fmt.Errorf("failed to analyze Docker image: %w", err)
		}
		imageFindings = findings
	}

	// Collect all findings
	var allFindings []rules.Finding
	allFindings = append(allFindings, goFindings...)
	allFindings = append(allFindings, dockerfileFindings...)
	allFindings = append(allFindings, imageFindings...)

	// Perform correlation analysis if both Go code and Dockerfile are provided
	if projectPath != "" && dockerfilePath != "" {
		corr := correlator.NewCorrelator()
		correlationResult := corr.CorrelateAll(goFindings, dockerfileFindings)
		allFindings = append(allFindings, correlationResult.Findings...)
	}

	// Apply rules engine
	result := engine.Evaluate(allFindings)

	// Generate report
	reporter := report.NewReporter(outputFormat)
	output, err := reporter.Generate(result)
	if err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	// Output report
	if outputFormat == "json" || outputFormat == "csv" {
		fmt.Println(output)
	} else {
		fmt.Print(output)
	}

	// Determine exit code - use SilenceUsage to prevent usage output on error
	if result.HasErrors() || (strictMode && result.HasWarnings()) {
		cmd.SilenceUsage = true
		cmd.SilenceErrors = true
		return fmt.Errorf("compatibility issues detected")
	}

	return nil
}

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of go-runtime-compat",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("go-runtime-compat v1.0.0")
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

// rulesCmd represents the rules command to list available rules
var rulesListCmd = &cobra.Command{
	Use:   "rules",
	Short: "List all compatibility rules",
	Run: func(cmd *cobra.Command, args []string) {
		engine := rules.NewEngine()
		rulesList := engine.ListRules()

		if outputFormat == "json" {
			data, _ := json.MarshalIndent(rulesList, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Println("Available Compatibility Rules:")
			fmt.Println("==============================")
			for _, r := range rulesList {
				fmt.Printf("\n[%s] %s\n", r.ID, r.Name)
				fmt.Printf("  Severity: %s\n", r.Severity)
				fmt.Printf("  Description: %s\n", r.Description)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(rulesListCmd)
	rulesListCmd.Flags().StringVarP(&outputFormat, "output", "o", "cli", "Output format: cli, json")
}

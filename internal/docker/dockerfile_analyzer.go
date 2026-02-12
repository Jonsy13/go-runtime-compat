// Package docker provides Docker-related analysis capabilities.
package docker

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/Jonsy13/go-runtime-compat/internal/rules"
)

// DockerfileAnalyzer analyzes Dockerfiles for container compatibility issues.
type DockerfileAnalyzer struct{}

// NewDockerfileAnalyzer creates a new Dockerfile analyzer.
func NewDockerfileAnalyzer() *DockerfileAnalyzer {
	return &DockerfileAnalyzer{}
}

// Stage represents a stage in a multi-stage Dockerfile.
type Stage struct {
	Name      string
	BaseImage string
	Line      int
	Commands  []DockerCommand
}

// DockerCommand represents a command in a Dockerfile.
type DockerCommand struct {
	Instruction string
	Arguments   string
	Line        int
}

// Analyze analyzes a Dockerfile for compatibility issues.
func (a *DockerfileAnalyzer) Analyze(dockerfilePath string) ([]rules.Finding, error) {
	file, err := os.Open(dockerfilePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	stages, err := a.parseDockerfile(file, dockerfilePath)
	if err != nil {
		return nil, err
	}

	var findings []rules.Finding

	// Check for multi-stage builds
	if len(stages) > 1 {
		findings = append(findings, rules.Finding{
			RuleID:   "CCG040",
			Category: rules.CategoryMultiStage,
			Severity: rules.SeverityInfo,
			Message:  fmt.Sprintf("Multi-stage build detected with %d stages", len(stages)),
			Location: rules.Location{
				File: dockerfilePath,
				Line: 1,
			},
			Details: map[string]interface{}{
				"stage_count": len(stages),
				"stages":      getStageNames(stages),
			},
			Suggestion: "Ensure the final stage has all required runtime dependencies",
		})
	}

	// Analyze each stage
	for i, stage := range stages {
		stageFindings := a.analyzeStage(stage, dockerfilePath, stages, i)
		findings = append(findings, stageFindings...)
	}

	return findings, nil
}

// parseDockerfile parses a Dockerfile into stages.
func (a *DockerfileAnalyzer) parseDockerfile(file *os.File, filePath string) ([]Stage, error) {
	var stages []Stage
	var currentStage *Stage

	scanner := bufio.NewScanner(file)
	lineNum := 0

	// Regex patterns
	fromPattern := regexp.MustCompile(`(?i)^FROM\s+(\S+)(?:\s+AS\s+(\S+))?`)
	instructionPattern := regexp.MustCompile(`(?i)^(FROM|RUN|COPY|ADD|ENV|ARG|WORKDIR|EXPOSE|CMD|ENTRYPOINT|LABEL|USER|VOLUME|ONBUILD|STOPSIGNAL|HEALTHCHECK|SHELL)\s+(.*)`)

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check for FROM instruction (new stage)
		if matches := fromPattern.FindStringSubmatch(line); matches != nil {
			baseImage := matches[1]
			stageName := ""
			if len(matches) > 2 {
				stageName = matches[2]
			}

			// Save previous stage
			if currentStage != nil {
				stages = append(stages, *currentStage)
			}

			currentStage = &Stage{
				Name:      stageName,
				BaseImage: baseImage,
				Line:      lineNum,
				Commands:  []DockerCommand{},
			}
		}

		// Parse other instructions
		if matches := instructionPattern.FindStringSubmatch(line); matches != nil {
			if currentStage != nil {
				currentStage.Commands = append(currentStage.Commands, DockerCommand{
					Instruction: strings.ToUpper(matches[1]),
					Arguments:   matches[2],
					Line:        lineNum,
				})
			}
		}
	}

	// Save last stage
	if currentStage != nil {
		stages = append(stages, *currentStage)
	}

	return stages, scanner.Err()
}

// analyzeStage analyzes a single Dockerfile stage.
func (a *DockerfileAnalyzer) analyzeStage(stage Stage, filePath string, allStages []Stage, stageIndex int) []rules.Finding {
	var findings []rules.Finding
	isFinalStage := stageIndex == len(allStages)-1

	// Check base image - only for final stage to avoid false positives from intermediate stages
	if isFinalStage {
		baseImageFindings := a.analyzeBaseImage(stage, filePath, true)
		findings = append(findings, baseImageFindings...)
	}

	// Check for CGO settings in RUN commands (for build stages)
	cgoFindings := a.analyzeCGOSettings(stage, filePath)
	findings = append(findings, cgoFindings...)

	// Check for multi-stage build issues
	if len(allStages) > 1 && isFinalStage {
		// This is the final stage
		multiStageFindings := a.analyzeMultiStageBuild(stage, allStages, filePath)
		findings = append(findings, multiStageFindings...)
	}

	return findings
}

// analyzeBaseImage analyzes the base image of a stage.
// isFinalStage indicates if this is the final runtime stage (for correlation purposes).
func (a *DockerfileAnalyzer) analyzeBaseImage(stage Stage, filePath string, isFinalStage bool) []rules.Finding {
	var findings []rules.Finding
	baseImage := strings.ToLower(stage.BaseImage)

	// Always add a finding with the final stage's base image info for correlation
	if isFinalStage {
		findings = append(findings, rules.Finding{
			RuleID:   "CCG035",
			Category: rules.CategoryDockerfile,
			Severity: rules.SeverityInfo,
			Message:  fmt.Sprintf("Final stage base image: %s", stage.BaseImage),
			Location: rules.Location{
				File:  filePath,
				Line:  stage.Line,
				Stage: stage.Name,
			},
			Details: map[string]interface{}{
				"base_image":     stage.BaseImage,
				"is_final_stage": true,
			},
			Suggestion: "This is the runtime image - ensure it has all required dependencies",
		})
	}

	// Check for scratch image
	if baseImage == "scratch" {
		findings = append(findings, rules.Finding{
			RuleID:   "CCG030",
			Category: rules.CategoryDockerfile,
			Severity: rules.SeverityInfo,
			Message:  "Using scratch base image - binary must be statically linked",
			Location: rules.Location{
				File:  filePath,
				Line:  stage.Line,
				Stage: stage.Name,
			},
			Details: map[string]interface{}{
				"base_image":     stage.BaseImage,
				"is_final_stage": isFinalStage,
			},
			Suggestion: "Ensure your Go binary is built with CGO_ENABLED=0 and static linking flags",
		})
	}

	// Check for distroless image
	if strings.Contains(baseImage, "distroless") {
		findings = append(findings, rules.Finding{
			RuleID:   "CCG031",
			Category: rules.CategoryDockerfile,
			Severity: rules.SeverityInfo,
			Message:  "Using distroless base image - limited shell and utility support",
			Location: rules.Location{
				File:  filePath,
				Line:  stage.Line,
				Stage: stage.Name,
			},
			Details: map[string]interface{}{
				"base_image":     stage.BaseImage,
				"is_final_stage": isFinalStage,
			},
			Suggestion: "Avoid exec.Command calls to shell or system utilities. Distroless images have minimal tooling.",
		})
	}

	// Check for Alpine image - only warn if it's the final stage
	if strings.Contains(baseImage, "alpine") && isFinalStage {
		findings = append(findings, rules.Finding{
			RuleID:   "CCG032",
			Category: rules.CategoryDockerfile,
			Severity: rules.SeverityWarning,
			Message:  "Using Alpine base image - uses musl libc instead of glibc",
			Location: rules.Location{
				File:  filePath,
				Line:  stage.Line,
				Stage: stage.Name,
			},
			Details: map[string]interface{}{
				"base_image":     stage.BaseImage,
				"is_final_stage": isFinalStage,
			},
			Suggestion: "CGO binaries compiled with glibc may not work. Use CGO_ENABLED=0 or compile with musl.",
		})
	}

	return findings
}

// analyzeCGOSettings analyzes CGO-related settings in the stage.
func (a *DockerfileAnalyzer) analyzeCGOSettings(stage Stage, filePath string) []rules.Finding {
	var findings []rules.Finding

	hasCGODisabled := false
	hasGoBuild := false

	for _, cmd := range stage.Commands {
		if cmd.Instruction == "RUN" || cmd.Instruction == "ENV" || cmd.Instruction == "ARG" {
			args := strings.ToLower(cmd.Arguments)

			// Check for CGO_ENABLED=0
			if strings.Contains(args, "cgo_enabled=0") {
				hasCGODisabled = true
			}

			// Check for go build
			if strings.Contains(args, "go build") {
				hasGoBuild = true
			}
		}
	}

	// If there's a go build without CGO_ENABLED=0, warn
	if hasGoBuild && !hasCGODisabled {
		// Check if base image is minimal
		baseImage := strings.ToLower(stage.BaseImage)
		if strings.Contains(baseImage, "scratch") || strings.Contains(baseImage, "distroless") || strings.Contains(baseImage, "alpine") {
			findings = append(findings, rules.Finding{
				RuleID:   "CCG033",
				Category: rules.CategoryDockerfile,
				Severity: rules.SeverityWarning,
				Message:  "Go build detected without CGO_ENABLED=0 in a minimal base image context",
				Location: rules.Location{
					File:  filePath,
					Line:  stage.Line,
					Stage: stage.Name,
				},
				Suggestion: "Add CGO_ENABLED=0 to ensure static linking: ENV CGO_ENABLED=0 or RUN CGO_ENABLED=0 go build ...",
			})
		}
	}

	return findings
}

// analyzeMultiStageBuild analyzes multi-stage build compatibility.
func (a *DockerfileAnalyzer) analyzeMultiStageBuild(finalStage Stage, allStages []Stage, filePath string) []rules.Finding {
	var findings []rules.Finding

	// Find build stages (stages that have go build)
	var buildStages []Stage
	for _, stage := range allStages[:len(allStages)-1] {
		for _, cmd := range stage.Commands {
			if cmd.Instruction == "RUN" && strings.Contains(strings.ToLower(cmd.Arguments), "go build") {
				buildStages = append(buildStages, stage)
				break
			}
		}
	}

	// Check for CGO mismatch between build and runtime stages
	finalBaseImage := strings.ToLower(finalStage.BaseImage)
	isMinimalRuntime := strings.Contains(finalBaseImage, "scratch") ||
		strings.Contains(finalBaseImage, "distroless") ||
		strings.Contains(finalBaseImage, "alpine")

	if isMinimalRuntime && len(buildStages) > 0 {
		for _, buildStage := range buildStages {
			hasCGODisabled := false
			for _, cmd := range buildStage.Commands {
				if strings.Contains(strings.ToLower(cmd.Arguments), "cgo_enabled=0") {
					hasCGODisabled = true
					break
				}
			}

			if !hasCGODisabled {
				findings = append(findings, rules.Finding{
					RuleID:   "CCG041",
					Category: rules.CategoryMultiStage,
					Severity: rules.SeverityWarning,
					Message:  "Build stage may produce dynamically linked binary incompatible with minimal runtime stage",
					Location: rules.Location{
						File:  filePath,
						Line:  buildStage.Line,
						Stage: buildStage.Name,
					},
					Details: map[string]interface{}{
						"build_stage":   buildStage.Name,
						"runtime_stage": finalStage.Name,
						"runtime_image": finalStage.BaseImage,
					},
					Suggestion: "Add CGO_ENABLED=0 to the build stage to ensure static linking",
				})
			}
		}
	}

	return findings
}

// getStageNames returns the names of all stages.
func getStageNames(stages []Stage) []string {
	names := make([]string, len(stages))
	for i, stage := range stages {
		if stage.Name != "" {
			names[i] = stage.Name
		} else {
			names[i] = stage.BaseImage
		}
	}
	return names
}

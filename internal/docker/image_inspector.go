// Package docker provides Docker-related analysis capabilities.
package docker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/Jonsy13/go-runtime-compat/internal/rules"
)

// ImageInspector inspects Docker images for compatibility issues.
type ImageInspector struct{}

// NewImageInspector creates a new Docker image inspector.
func NewImageInspector() *ImageInspector {
	return &ImageInspector{}
}

// ImageInfo contains information about a Docker image.
type ImageInfo struct {
	ID           string   `json:"Id"`
	RepoTags     []string `json:"RepoTags"`
	Architecture string   `json:"Architecture"`
	OS           string   `json:"Os"`
	Config       struct {
		Env        []string `json:"Env"`
		Entrypoint []string `json:"Entrypoint"`
		Cmd        []string `json:"Cmd"`
		WorkingDir string   `json:"WorkingDir"`
	} `json:"Config"`
	RootFS struct {
		Type   string   `json:"Type"`
		Layers []string `json:"Layers"`
	} `json:"RootFS"`
}

// LddOutput represents the output of ldd command.
type LddOutput struct {
	Library    string
	Address    string
	NotFound   bool
	StaticLink bool
}

// Analyze analyzes a Docker image for compatibility issues.
func (i *ImageInspector) Analyze(imageName string) ([]rules.Finding, error) {
	var findings []rules.Finding

	// Inspect the image
	imageInfo, err := i.inspectImage(imageName)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect image: %w", err)
	}

	// Check for dynamic linking
	lddFindings, err := i.checkDynamicLinking(imageName, imageInfo)
	if err != nil {
		// Log but continue - ldd might not be available
		findings = append(findings, rules.Finding{
			RuleID:   "CCG020",
			Category: rules.CategoryDynamicLinking,
			Severity: rules.SeverityInfo,
			Message:  "Could not check dynamic linking: " + err.Error(),
			Location: rules.Location{
				File: imageName,
			},
			Suggestion: "Manually verify the binary is statically linked if using scratch/distroless images",
		})
	} else {
		findings = append(findings, lddFindings...)
	}

	// Check image configuration
	configFindings := i.checkImageConfig(imageName, imageInfo)
	findings = append(findings, configFindings...)

	return findings, nil
}

// inspectImage runs docker inspect on the image.
func (i *ImageInspector) inspectImage(imageName string) (*ImageInfo, error) {
	cmd := exec.Command("docker", "inspect", imageName)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("docker inspect failed: %s", stderr.String())
	}

	var images []ImageInfo
	if err := json.Unmarshal(stdout.Bytes(), &images); err != nil {
		return nil, fmt.Errorf("failed to parse docker inspect output: %w", err)
	}

	if len(images) == 0 {
		return nil, fmt.Errorf("no image found with name: %s", imageName)
	}

	return &images[0], nil
}

// checkDynamicLinking checks if binaries in the image are dynamically linked.
func (i *ImageInspector) checkDynamicLinking(imageName string, imageInfo *ImageInfo) ([]rules.Finding, error) {
	var findings []rules.Finding

	// Try to find the main binary
	entrypoint := ""
	if len(imageInfo.Config.Entrypoint) > 0 {
		entrypoint = imageInfo.Config.Entrypoint[0]
	} else if len(imageInfo.Config.Cmd) > 0 {
		entrypoint = imageInfo.Config.Cmd[0]
	}

	if entrypoint == "" {
		return findings, nil
	}

	// Run ldd inside the container
	lddOutput, err := i.runLddInContainer(imageName, entrypoint)
	if err != nil {
		return nil, err
	}

	// Parse ldd output
	lddResults := i.parseLddOutput(lddOutput)

	// Check for issues
	for _, result := range lddResults {
		if result.StaticLink {
			findings = append(findings, rules.Finding{
				RuleID:   "CCG020",
				Category: rules.CategoryDynamicLinking,
				Severity: rules.SeverityInfo,
				Message:  "Binary is statically linked - compatible with scratch/distroless images",
				Location: rules.Location{
					File: imageName,
				},
				Details: map[string]interface{}{
					"binary": entrypoint,
				},
			})
			return findings, nil
		}

		if result.NotFound {
			findings = append(findings, rules.Finding{
				RuleID:   "CCG021",
				Category: rules.CategoryDynamicLinking,
				Severity: rules.SeverityError,
				Message:  fmt.Sprintf("Missing shared library: %s", result.Library),
				Location: rules.Location{
					File: imageName,
				},
				Details: map[string]interface{}{
					"binary":  entrypoint,
					"library": result.Library,
				},
				Suggestion: "Install the missing library or rebuild the binary with static linking (CGO_ENABLED=0)",
			})
		}

		// Check for glibc dependency
		if strings.Contains(result.Library, "libc.so") || strings.Contains(result.Library, "glibc") {
			findings = append(findings, rules.Finding{
				RuleID:   "CCG022",
				Category: rules.CategoryDynamicLinking,
				Severity: rules.SeverityWarning,
				Message:  "Binary depends on glibc - may not work in Alpine (musl) or scratch images",
				Location: rules.Location{
					File: imageName,
				},
				Details: map[string]interface{}{
					"binary":  entrypoint,
					"library": result.Library,
				},
				Suggestion: "Rebuild with CGO_ENABLED=0 for static linking, or use a glibc-based image",
			})
		}
	}

	// If we found dynamic libraries but no specific issues
	if len(lddResults) > 0 && len(findings) == 0 {
		findings = append(findings, rules.Finding{
			RuleID:   "CCG020",
			Category: rules.CategoryDynamicLinking,
			Severity: rules.SeverityWarning,
			Message:  "Binary is dynamically linked - requires shared libraries at runtime",
			Location: rules.Location{
				File: imageName,
			},
			Details: map[string]interface{}{
				"binary":    entrypoint,
				"libraries": len(lddResults),
			},
			Suggestion: "Ensure all required libraries are available in the runtime image, or rebuild with static linking",
		})
	}

	return findings, nil
}

// runLddInContainer runs ldd on a binary inside the container.
func (i *ImageInspector) runLddInContainer(imageName, binary string) (string, error) {
	// First try to run ldd directly
	cmd := exec.Command("docker", "run", "--rm", "--entrypoint", "", imageName, "ldd", binary)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// ldd might not be available, try with a helper image
		cmd = exec.Command("docker", "run", "--rm", "-v", "/:/host:ro", "alpine", "ldd", "/host"+binary)
		stdout.Reset()
		stderr.Reset()
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("ldd failed: %s", stderr.String())
		}
	}

	return stdout.String(), nil
}

// parseLddOutput parses the output of ldd command.
func (i *ImageInspector) parseLddOutput(output string) []LddOutput {
	var results []LddOutput

	// Check for static binary
	if strings.Contains(output, "not a dynamic executable") || strings.Contains(output, "statically linked") {
		return []LddOutput{{StaticLink: true}}
	}

	// Parse each line
	lines := strings.Split(output, "\n")
	libPattern := regexp.MustCompile(`^\s*(\S+)\s*(?:=>)?\s*(\S+)?\s*\(?(0x[0-9a-f]+)?\)?`)
	notFoundPattern := regexp.MustCompile(`not found`)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		result := LddOutput{}

		if notFoundPattern.MatchString(line) {
			result.NotFound = true
		}

		if matches := libPattern.FindStringSubmatch(line); matches != nil {
			result.Library = matches[1]
			if len(matches) > 2 && matches[2] != "" {
				result.Address = matches[2]
			}
		}

		if result.Library != "" {
			results = append(results, result)
		}
	}

	return results
}

// checkImageConfig checks the image configuration for compatibility issues.
func (i *ImageInspector) checkImageConfig(imageName string, imageInfo *ImageInfo) []rules.Finding {
	var findings []rules.Finding

	// Check environment variables for CGO settings
	for _, env := range imageInfo.Config.Env {
		if strings.HasPrefix(env, "CGO_ENABLED=") {
			value := strings.TrimPrefix(env, "CGO_ENABLED=")
			if value == "1" {
				findings = append(findings, rules.Finding{
					RuleID:   "CCG010",
					Category: rules.CategoryCGO,
					Severity: rules.SeverityWarning,
					Message:  "CGO_ENABLED=1 found in image environment",
					Location: rules.Location{
						File: imageName,
					},
					Details: map[string]interface{}{
						"env": env,
					},
					Suggestion: "If the image uses a minimal base, ensure CGO dependencies are satisfied",
				})
			}
		}
	}

	// Check for shell in entrypoint/cmd
	shellCommands := []string{"/bin/sh", "/bin/bash", "sh", "bash"}
	for _, shell := range shellCommands {
		if len(imageInfo.Config.Entrypoint) > 0 && imageInfo.Config.Entrypoint[0] == shell {
			findings = append(findings, rules.Finding{
				RuleID:   "CCG002",
				Category: rules.CategoryExecCommand,
				Severity: rules.SeverityInfo,
				Message:  "Image entrypoint uses shell - requires shell in base image",
				Location: rules.Location{
					File: imageName,
				},
				Details: map[string]interface{}{
					"entrypoint": imageInfo.Config.Entrypoint,
				},
				Suggestion: "Ensure the base image has the required shell, or use a direct binary entrypoint",
			})
			break
		}
	}

	return findings
}

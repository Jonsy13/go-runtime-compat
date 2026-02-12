// Package correlator correlates Go code dependencies with Dockerfile capabilities.
package correlator

import (
	"fmt"
	"strings"

	"github.com/Jonsy13/go-runtime-compat/internal/rules"
)

// DependencyType represents the type of dependency detected in Go code.
type DependencyType string

const (
	DepExecCommand  DependencyType = "exec_command"
	DepShellCommand DependencyType = "shell_command"
	DepSystemBinary DependencyType = "system_binary"
	DepCGO          DependencyType = "cgo"
	DepDynamicLink  DependencyType = "dynamic_link"
)

// Dependency represents a dependency detected in Go code.
type Dependency struct {
	Type     DependencyType
	Name     string            // Command name or library name
	Location rules.Location    // Where it was detected
	Details  map[string]interface{}
}

// DockerfileCapability represents what a Dockerfile can provide.
type DockerfileCapability struct {
	HasShell          bool
	HasGlibc          bool
	HasMusl           bool
	IsMinimalImage    bool     // scratch, distroless
	IsAlpineImage     bool
	CGODisabled       bool
	AvailableBinaries []string // Binaries available in the image
	FinalBaseImage    string
	BuildBaseImage    string
}

// CorrelationResult represents the result of correlating dependencies with Dockerfile.
type CorrelationResult struct {
	Dependencies []Dependency
	Capabilities DockerfileCapability
	Findings     []rules.Finding
}

// Correlator correlates Go code dependencies with Dockerfile capabilities.
type Correlator struct{}

// NewCorrelator creates a new Correlator.
func NewCorrelator() *Correlator {
	return &Correlator{}
}

// ExtractDependencies extracts dependencies from Go analyzer findings.
func (c *Correlator) ExtractDependencies(goFindings []rules.Finding) []Dependency {
	var deps []Dependency

	for _, f := range goFindings {
		switch f.Category {
		case rules.CategoryExecCommand:
			dep := Dependency{
				Location: f.Location,
				Details:  f.Details,
			}

			// Determine dependency type based on rule ID
			switch f.RuleID {
			case "CCG002": // Shell command
				dep.Type = DepShellCommand
				if cmd, ok := f.Details["command"].(string); ok {
					dep.Name = cmd
				}
			case "CCG003": // System binary
				dep.Type = DepSystemBinary
				if cmd, ok := f.Details["command"].(string); ok {
					dep.Name = cmd
				}
			default: // CCG001 - generic exec.Command
				dep.Type = DepExecCommand
				if cmd, ok := f.Details["command"].(string); ok {
					dep.Name = cmd
				}
			}
			deps = append(deps, dep)

		case rules.CategoryCGO:
			deps = append(deps, Dependency{
				Type:     DepCGO,
				Name:     "CGO",
				Location: f.Location,
				Details:  f.Details,
			})

		case rules.CategoryDynamicLink:
			dep := Dependency{
				Type:     DepDynamicLink,
				Location: f.Location,
				Details:  f.Details,
			}
			if lib, ok := f.Details["library"].(string); ok {
				dep.Name = lib
			}
			deps = append(deps, dep)
		}
	}

	return deps
}

// ExtractCapabilities extracts capabilities from Dockerfile analyzer findings and stages.
func (c *Correlator) ExtractCapabilities(dockerfileFindings []rules.Finding) DockerfileCapability {
	cap := DockerfileCapability{}

	for _, f := range dockerfileFindings {
		if f.Details == nil {
			continue
		}

		baseImage, _ := f.Details["base_image"].(string)
		isFinalStage, _ := f.Details["is_final_stage"].(bool)

		switch f.RuleID {
		case "CCG035": // Final stage base image info
			if isFinalStage {
				cap.FinalBaseImage = baseImage
				// Infer capabilities from the final stage base image
				c.inferCapabilitiesFromImage(baseImage, &cap)
			}
		case "CCG030": // Scratch
			if isFinalStage {
				cap.IsMinimalImage = true
				cap.HasShell = false
				cap.HasGlibc = false
				cap.FinalBaseImage = baseImage
			}
		case "CCG031": // Distroless
			if isFinalStage {
				cap.IsMinimalImage = true
				cap.HasShell = false
				cap.HasGlibc = true // distroless has glibc
				cap.FinalBaseImage = baseImage
			}
		case "CCG032": // Alpine (only reported for final stage now)
			cap.IsAlpineImage = true
			cap.HasShell = true
			cap.HasMusl = true
			cap.HasGlibc = false
			cap.FinalBaseImage = baseImage
		case "CCG033": // Missing CGO_ENABLED=0
			cap.CGODisabled = false
		case "CCG040": // Multi-stage
			if stages, ok := f.Details["stages"].([]string); ok && len(stages) > 0 {
				// Don't override FinalBaseImage from CCG035
				if cap.FinalBaseImage == "" {
					cap.FinalBaseImage = stages[len(stages)-1]
				}
			}
		}
	}

	// Set available binaries based on image type
	cap.AvailableBinaries = c.inferAvailableBinaries(cap)

	return cap
}

// inferCapabilitiesFromImage infers capabilities from a base image name.
func (c *Correlator) inferCapabilitiesFromImage(baseImage string, cap *DockerfileCapability) {
	imageLower := strings.ToLower(baseImage)

	// Check for minimal images first
	if imageLower == "scratch" {
		cap.IsMinimalImage = true
		cap.HasShell = false
		cap.HasGlibc = false
		return
	}

	if strings.Contains(imageLower, "distroless") {
		cap.IsMinimalImage = true
		cap.HasShell = false
		cap.HasGlibc = true
		return
	}

	// Check for Alpine
	if strings.Contains(imageLower, "alpine") {
		cap.IsAlpineImage = true
		cap.HasShell = true
		cap.HasMusl = true
		cap.HasGlibc = false
		return
	}

	// Check for full-featured Linux distributions
	// UBI (Universal Base Image) - Red Hat
	if strings.Contains(imageLower, "ubi") || strings.Contains(imageLower, "redhat") ||
		strings.Contains(imageLower, "rhel") || strings.Contains(imageLower, "centos") ||
		strings.Contains(imageLower, "fedora") {
		cap.HasShell = true
		cap.HasGlibc = true
		cap.IsMinimalImage = false
		return
	}

	// Debian/Ubuntu based
	if strings.Contains(imageLower, "debian") || strings.Contains(imageLower, "ubuntu") {
		cap.HasShell = true
		cap.HasGlibc = true
		cap.IsMinimalImage = false
		return
	}

	// Golang build images
	if strings.Contains(imageLower, "golang") {
		cap.HasShell = true
		cap.HasGlibc = true
		cap.IsMinimalImage = false
		return
	}

	// Default: assume it's a full-featured image with shell and glibc
	// This is safer than assuming it's minimal
	cap.HasShell = true
	cap.HasGlibc = true
	cap.IsMinimalImage = false
}

// inferAvailableBinaries infers available binaries based on image type.
func (c *Correlator) inferAvailableBinaries(cap DockerfileCapability) []string {
	if cap.IsMinimalImage && !cap.HasShell {
		return []string{} // scratch/distroless have no binaries
	}

	if cap.IsAlpineImage {
		// Alpine has busybox-based utilities
		return []string{
			"sh", "ls", "cat", "grep", "awk", "sed", "find",
			"ps", "kill", "chmod", "chown", "wget", "tar", "gzip",
		}
	}

	// Full-featured Linux distributions (Debian, Ubuntu, RHEL, UBI, etc.)
	return []string{
		"sh", "bash", "ls", "cat", "grep", "awk", "sed", "find",
		"ps", "kill", "chmod", "chown", "curl", "wget", "tar", "gzip",
		"mount", "umount",
	}
}

// Correlate correlates dependencies with Dockerfile capabilities.
func (c *Correlator) Correlate(deps []Dependency, cap DockerfileCapability) []rules.Finding {
	var findings []rules.Finding

	for _, dep := range deps {
		switch dep.Type {
		case DepShellCommand:
			if !cap.HasShell {
				findings = append(findings, rules.Finding{
					RuleID:   "CCG100",
					Category: rules.CategoryCorrelation,
					Severity: rules.SeverityError,
					Message:  fmt.Sprintf("Shell command '%s' used but Dockerfile uses %s which has no shell", dep.Name, cap.FinalBaseImage),
					Location: dep.Location,
					Details: map[string]interface{}{
						"command":     dep.Name,
						"base_image":  cap.FinalBaseImage,
						"has_shell":   cap.HasShell,
						"correlation": "shell_unavailable",
					},
					Suggestion: "Either use a base image with a shell (alpine, debian) or remove shell command usage from Go code",
				})
			}

		case DepSystemBinary:
			if !c.isBinaryAvailable(dep.Name, cap) {
				findings = append(findings, rules.Finding{
					RuleID:   "CCG101",
					Category: rules.CategoryCorrelation,
					Severity: rules.SeverityError,
					Message:  fmt.Sprintf("System binary '%s' used but may not be available in %s", dep.Name, cap.FinalBaseImage),
					Location: dep.Location,
					Details: map[string]interface{}{
						"command":            dep.Name,
						"base_image":         cap.FinalBaseImage,
						"available_binaries": cap.AvailableBinaries,
						"correlation":        "binary_unavailable",
					},
					Suggestion: fmt.Sprintf("Install '%s' in Dockerfile or use a pure Go alternative", dep.Name),
				})
			}

		case DepExecCommand:
			// Generic exec.Command - warn if minimal image
			if cap.IsMinimalImage && dep.Name != "" {
				findings = append(findings, rules.Finding{
					RuleID:   "CCG102",
					Category: rules.CategoryCorrelation,
					Severity: rules.SeverityWarning,
					Message:  fmt.Sprintf("exec.Command('%s') used with minimal base image %s - verify command availability", dep.Name, cap.FinalBaseImage),
					Location: dep.Location,
					Details: map[string]interface{}{
						"command":     dep.Name,
						"base_image":  cap.FinalBaseImage,
						"is_minimal":  cap.IsMinimalImage,
						"correlation": "potential_missing_command",
					},
					Suggestion: "Verify the command exists in your final container image or use pure Go alternatives",
				})
			}

		case DepCGO:
			// CGO requires glibc (or musl if compiled for it)
			if cap.IsMinimalImage && !cap.HasGlibc && !cap.CGODisabled {
				findings = append(findings, rules.Finding{
					RuleID:   "CCG103",
					Category: rules.CategoryCorrelation,
					Severity: rules.SeverityError,
					Message:  fmt.Sprintf("CGO detected but Dockerfile uses %s which has no glibc and CGO is not disabled", cap.FinalBaseImage),
					Location: dep.Location,
					Details: map[string]interface{}{
						"base_image":   cap.FinalBaseImage,
						"has_glibc":    cap.HasGlibc,
						"cgo_disabled": cap.CGODisabled,
						"correlation":  "cgo_glibc_mismatch",
					},
					Suggestion: "Add CGO_ENABLED=0 to your Dockerfile build stage or use a base image with glibc",
				})
			}

			if cap.IsAlpineImage && !cap.CGODisabled {
				findings = append(findings, rules.Finding{
					RuleID:   "CCG104",
					Category: rules.CategoryCorrelation,
					Severity: rules.SeverityError,
					Message:  "CGO detected but Dockerfile uses Alpine which has musl instead of glibc",
					Location: dep.Location,
					Details: map[string]interface{}{
						"base_image":   cap.FinalBaseImage,
						"has_musl":     cap.HasMusl,
						"has_glibc":    cap.HasGlibc,
						"cgo_disabled": cap.CGODisabled,
						"correlation":  "cgo_musl_mismatch",
					},
					Suggestion: "Add CGO_ENABLED=0 to disable CGO, or compile with musl, or use a glibc-based image (debian, ubuntu)",
				})
			}

		case DepDynamicLink:
			if cap.IsMinimalImage {
				findings = append(findings, rules.Finding{
					RuleID:   "CCG105",
					Category: rules.CategoryCorrelation,
					Severity: rules.SeverityError,
					Message:  fmt.Sprintf("Dynamic library '%s' required but Dockerfile uses minimal image %s", dep.Name, cap.FinalBaseImage),
					Location: dep.Location,
					Details: map[string]interface{}{
						"library":     dep.Name,
						"base_image":  cap.FinalBaseImage,
						"is_minimal":  cap.IsMinimalImage,
						"correlation": "dynamic_link_unavailable",
					},
					Suggestion: "Build with CGO_ENABLED=0 for static linking or use a base image with required libraries",
				})
			}
		}
	}

	// Check for undetected but potential issues
	if len(deps) == 0 && cap.IsMinimalImage {
		// No explicit dependencies but using minimal image - add info
		findings = append(findings, rules.Finding{
			RuleID:   "CCG110",
			Category: rules.CategoryCorrelation,
			Severity: rules.SeverityInfo,
			Message:  fmt.Sprintf("Using minimal base image %s - ensure binary is statically linked", cap.FinalBaseImage),
			Location: rules.Location{
				File: "Dockerfile",
				Line: 1,
			},
			Details: map[string]interface{}{
				"base_image":  cap.FinalBaseImage,
				"is_minimal":  cap.IsMinimalImage,
				"correlation": "minimal_image_static_link_reminder",
			},
			Suggestion: "Verify your Go binary is built with CGO_ENABLED=0 and appropriate ldflags for static linking",
		})
	}

	return findings
}

// isBinaryAvailable checks if a binary is available in the image.
func (c *Correlator) isBinaryAvailable(binary string, cap DockerfileCapability) bool {
	// Normalize binary name (remove path prefix)
	binaryName := binary
	if idx := strings.LastIndex(binary, "/"); idx != -1 {
		binaryName = binary[idx+1:]
	}

	// Check if in available binaries list
	for _, b := range cap.AvailableBinaries {
		if b == binaryName {
			return true
		}
	}

	// Special cases
	if cap.IsMinimalImage && !cap.HasShell {
		return false // scratch/distroless have nothing
	}

	// curl is not in Alpine by default
	if binaryName == "curl" && cap.IsAlpineImage {
		return false
	}

	// bash is not in Alpine by default (only sh via busybox)
	if binaryName == "bash" && cap.IsAlpineImage {
		return false
	}

	return false
}

// CorrelateAll performs full correlation analysis.
func (c *Correlator) CorrelateAll(goFindings, dockerfileFindings []rules.Finding) *CorrelationResult {
	deps := c.ExtractDependencies(goFindings)
	caps := c.ExtractCapabilities(dockerfileFindings)
	correlationFindings := c.Correlate(deps, caps)

	return &CorrelationResult{
		Dependencies: deps,
		Capabilities: caps,
		Findings:     correlationFindings,
	}
}

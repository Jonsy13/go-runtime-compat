// Package rules provides the compatibility rules engine for ccg.
package rules

// Engine is the compatibility rules engine that evaluates findings.
type Engine struct {
	rules map[string]*Rule
}

// NewEngine creates a new rules engine with default rules.
func NewEngine() *Engine {
	e := &Engine{
		rules: make(map[string]*Rule),
	}
	e.registerDefaultRules()
	return e
}

// registerDefaultRules registers all default compatibility rules.
func (e *Engine) registerDefaultRules() {
	defaultRules := []Rule{
		// exec.Command rules
		{
			ID:          "CCG001",
			Name:        "exec.Command Usage",
			Description: "Detects usage of exec.Command which may fail in minimal container images",
			Severity:    SeverityWarning,
			Category:    CategoryExecCommand,
			Enabled:     true,
		},
		{
			ID:          "CCG002",
			Name:        "Shell Command Execution",
			Description: "Detects shell command execution (sh, bash) - verify shell availability in container",
			Severity:    SeverityWarning,
			Category:    CategoryExecCommand,
			Enabled:     true,
		},
		{
			ID:          "CCG003",
			Name:        "System Binary Dependency",
			Description: "Detects calls to system binaries that may not exist in minimal containers",
			Severity:    SeverityWarning,
			Category:    CategoryExecCommand,
			Enabled:     true,
		},

		// CGO rules
		{
			ID:          "CCG010",
			Name:        "CGO Enabled",
			Description: "Detects CGO usage which requires glibc and may not work in Alpine/scratch images",
			Severity:    SeverityError,
			Category:    CategoryCGO,
			Enabled:     true,
		},
		{
			ID:          "CCG011",
			Name:        "CGO Import",
			Description: "Detects import of 'C' package indicating CGO dependency",
			Severity:    SeverityError,
			Category:    CategoryCGO,
			Enabled:     true,
		},

		// Dynamic linking rules
		{
			ID:          "CCG020",
			Name:        "Dynamic Linking Detected",
			Description: "Binary is dynamically linked and requires shared libraries",
			Severity:    SeverityError,
			Category:    CategoryDynamicLinking,
			Enabled:     true,
		},
		{
			ID:          "CCG021",
			Name:        "Missing Shared Library",
			Description: "Required shared library not found in container image",
			Severity:    SeverityError,
			Category:    CategoryDynamicLinking,
			Enabled:     true,
		},
		{
			ID:          "CCG022",
			Name:        "glibc Dependency",
			Description: "Binary depends on glibc which is not available in Alpine (uses musl) or scratch images",
			Severity:    SeverityError,
			Category:    CategoryDynamicLinking,
			Enabled:     true,
		},

		// Dockerfile rules
		{
			ID:          "CCG030",
			Name:        "Scratch Base Image",
			Description: "Using scratch base image requires statically linked binary",
			Severity:    SeverityInfo,
			Category:    CategoryDockerfile,
			Enabled:     true,
		},
		{
			ID:          "CCG031",
			Name:        "Distroless Base Image",
			Description: "Using distroless base image has limited shell and utility support",
			Severity:    SeverityInfo,
			Category:    CategoryDockerfile,
			Enabled:     true,
		},
		{
			ID:          "CCG032",
			Name:        "Alpine Base Image",
			Description: "Alpine uses musl libc instead of glibc - CGO binaries may not work",
			Severity:    SeverityWarning,
			Category:    CategoryDockerfile,
			Enabled:     true,
		},
		{
			ID:          "CCG033",
			Name:        "Missing CGO_ENABLED=0",
			Description: "Go build without CGO_ENABLED=0 may produce dynamically linked binary",
			Severity:    SeverityWarning,
			Category:    CategoryDockerfile,
			Enabled:     true,
		},
		{
			ID:          "CCG035",
			Name:        "Final Stage Base Image",
			Description: "Information about the final runtime stage base image",
			Severity:    SeverityInfo,
			Category:    CategoryDockerfile,
			Enabled:     true,
		},

		// Multi-stage rules
		{
			ID:          "CCG040",
			Name:        "Multi-stage Build Detected",
			Description: "Multi-stage build detected - ensure final stage has required dependencies",
			Severity:    SeverityInfo,
			Category:    CategoryMultiStage,
			Enabled:     true,
		},
		{
			ID:          "CCG041",
			Name:        "Build Stage CGO Mismatch",
			Description: "Build stage CGO setting may not match runtime stage capabilities",
			Severity:    SeverityWarning,
			Category:    CategoryMultiStage,
			Enabled:     true,
		},

		// Base image rules
		{
			ID:          "CCG050",
			Name:        "Incompatible Base Image",
			Description: "Base image may not support the binary's requirements",
			Severity:    SeverityError,
			Category:    CategoryBaseImage,
			Enabled:     true,
		},

		// Correlation rules (Go code + Dockerfile)
		{
			ID:          "CCG100",
			Name:        "Shell Command Incompatible with Base Image",
			Description: "Shell command used in Go code but Dockerfile base image has no shell",
			Severity:    SeverityError,
			Category:    CategoryCorrelation,
			Enabled:     true,
		},
		{
			ID:          "CCG101",
			Name:        "System Binary Unavailable",
			Description: "System binary used in Go code may not be available in Dockerfile base image",
			Severity:    SeverityError,
			Category:    CategoryCorrelation,
			Enabled:     true,
		},
		{
			ID:          "CCG102",
			Name:        "Command Availability Warning",
			Description: "exec.Command used with minimal base image - verify command availability",
			Severity:    SeverityWarning,
			Category:    CategoryCorrelation,
			Enabled:     true,
		},
		{
			ID:          "CCG103",
			Name:        "CGO Without glibc",
			Description: "CGO detected but Dockerfile base image has no glibc and CGO is not disabled",
			Severity:    SeverityError,
			Category:    CategoryCorrelation,
			Enabled:     true,
		},
		{
			ID:          "CCG104",
			Name:        "CGO with musl Mismatch",
			Description: "CGO detected but Dockerfile uses Alpine which has musl instead of glibc",
			Severity:    SeverityError,
			Category:    CategoryCorrelation,
			Enabled:     true,
		},
		{
			ID:          "CCG105",
			Name:        "Dynamic Library Unavailable",
			Description: "Dynamic library required but Dockerfile uses minimal image without it",
			Severity:    SeverityError,
			Category:    CategoryCorrelation,
			Enabled:     true,
		},
		{
			ID:          "CCG110",
			Name:        "Minimal Image Static Link Reminder",
			Description: "Using minimal base image - ensure binary is statically linked",
			Severity:    SeverityInfo,
			Category:    CategoryCorrelation,
			Enabled:     true,
		},
	}

	for i := range defaultRules {
		e.rules[defaultRules[i].ID] = &defaultRules[i]
	}
}

// Evaluate evaluates a list of findings and returns the result.
func (e *Engine) Evaluate(findings []Finding) *Result {
	result := &Result{
		Findings: findings,
		Summary: Summary{
			ByCategory: make(map[Category]int),
		},
	}

	for _, f := range findings {
		result.Summary.TotalFindings++
		result.Summary.ByCategory[f.Category]++

		switch f.Severity {
		case SeverityError:
			result.Summary.ErrorCount++
		case SeverityWarning:
			result.Summary.WarningCount++
		case SeverityInfo:
			result.Summary.InfoCount++
		}
	}

	result.Passed = result.Summary.ErrorCount == 0

	return result
}

// ListRules returns all registered rules.
func (e *Engine) ListRules() []Rule {
	rules := make([]Rule, 0, len(e.rules))
	for _, r := range e.rules {
		rules = append(rules, *r)
	}
	return rules
}

// GetRule returns a rule by ID.
func (e *Engine) GetRule(id string) *Rule {
	return e.rules[id]
}

// EnableRule enables a rule by ID.
func (e *Engine) EnableRule(id string) {
	if r, ok := e.rules[id]; ok {
		r.Enabled = true
	}
}

// DisableRule disables a rule by ID.
func (e *Engine) DisableRule(id string) {
	if r, ok := e.rules[id]; ok {
		r.Enabled = false
	}
}

// IsRuleEnabled returns true if the rule is enabled.
func (e *Engine) IsRuleEnabled(id string) bool {
	if r, ok := e.rules[id]; ok {
		return r.Enabled
	}
	return false
}

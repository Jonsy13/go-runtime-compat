// Package rules provides the compatibility rules engine for ccg.
package rules

// Severity represents the severity level of a finding.
type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
	SeverityInfo    Severity = "info"
)

// Category represents the category of a finding.
type Category string

const (
	CategoryExecCommand    Category = "exec_command"
	CategoryCGO            Category = "cgo"
	CategoryDynamicLinking Category = "dynamic_linking"
	CategoryDynamicLink    Category = "dynamic_link"
	CategoryDockerfile     Category = "dockerfile"
	CategoryBaseImage      Category = "base_image"
	CategoryMultiStage     Category = "multi_stage"
	CategoryCorrelation    Category = "correlation"
)

// Finding represents a single compatibility issue found during analysis.
type Finding struct {
	// RuleID is the unique identifier of the rule that generated this finding.
	RuleID string `json:"rule_id"`

	// Category is the category of the finding.
	Category Category `json:"category"`

	// Severity is the severity level of the finding.
	Severity Severity `json:"severity"`

	// Message is a human-readable description of the finding.
	Message string `json:"message"`

	// Location is the file and line where the issue was found.
	Location Location `json:"location"`

	// Details contains additional context about the finding.
	Details map[string]interface{} `json:"details,omitempty"`

	// Suggestion provides a recommended fix for the issue.
	Suggestion string `json:"suggestion,omitempty"`
}

// Location represents the location of a finding in source code or configuration.
type Location struct {
	// File is the path to the file.
	File string `json:"file"`

	// Line is the line number (1-indexed).
	Line int `json:"line,omitempty"`

	// Column is the column number (1-indexed).
	Column int `json:"column,omitempty"`

	// Stage is the Docker build stage name (for multi-stage Dockerfiles).
	Stage string `json:"stage,omitempty"`
}

// Rule represents a compatibility rule.
type Rule struct {
	// ID is the unique identifier of the rule.
	ID string `json:"id"`

	// Name is the human-readable name of the rule.
	Name string `json:"name"`

	// Description is a detailed description of what the rule checks.
	Description string `json:"description"`

	// Severity is the default severity of findings from this rule.
	Severity Severity `json:"severity"`

	// Category is the category this rule belongs to.
	Category Category `json:"category"`

	// Enabled indicates whether the rule is enabled.
	Enabled bool `json:"enabled"`
}

// Result represents the overall result of the compatibility analysis.
type Result struct {
	// Findings is the list of all findings.
	Findings []Finding `json:"findings"`

	// Summary contains aggregated statistics.
	Summary Summary `json:"summary"`

	// Passed indicates whether the analysis passed (no errors).
	Passed bool `json:"passed"`
}

// Summary contains aggregated statistics about the findings.
type Summary struct {
	// TotalFindings is the total number of findings.
	TotalFindings int `json:"total_findings"`

	// ErrorCount is the number of error-level findings.
	ErrorCount int `json:"error_count"`

	// WarningCount is the number of warning-level findings.
	WarningCount int `json:"warning_count"`

	// InfoCount is the number of info-level findings.
	InfoCount int `json:"info_count"`

	// ByCategory contains counts grouped by category.
	ByCategory map[Category]int `json:"by_category"`
}

// HasErrors returns true if there are any error-level findings.
func (r *Result) HasErrors() bool {
	return r.Summary.ErrorCount > 0
}

// HasWarnings returns true if there are any warning-level findings.
func (r *Result) HasWarnings() bool {
	return r.Summary.WarningCount > 0
}

package rules

import (
	"testing"
)

func TestNewEngine(t *testing.T) {
	engine := NewEngine()
	if engine == nil {
		t.Fatal("NewEngine() returned nil")
	}

	rules := engine.ListRules()
	if len(rules) == 0 {
		t.Error("NewEngine() should register default rules")
	}
}

func TestEngineEvaluate(t *testing.T) {
	tests := []struct {
		name           string
		findings       []Finding
		expectedErrors int
		expectedWarn   int
		expectedInfo   int
		expectedPassed bool
	}{
		{
			name:           "empty findings",
			findings:       []Finding{},
			expectedErrors: 0,
			expectedWarn:   0,
			expectedInfo:   0,
			expectedPassed: true,
		},
		{
			name: "single error finding",
			findings: []Finding{
				{
					RuleID:   "CCG001",
					Category: CategoryExecCommand,
					Severity: SeverityError,
					Message:  "Test error",
				},
			},
			expectedErrors: 1,
			expectedWarn:   0,
			expectedInfo:   0,
			expectedPassed: false,
		},
		{
			name: "single warning finding",
			findings: []Finding{
				{
					RuleID:   "CCG001",
					Category: CategoryExecCommand,
					Severity: SeverityWarning,
					Message:  "Test warning",
				},
			},
			expectedErrors: 0,
			expectedWarn:   1,
			expectedInfo:   0,
			expectedPassed: true,
		},
		{
			name: "single info finding",
			findings: []Finding{
				{
					RuleID:   "CCG001",
					Category: CategoryExecCommand,
					Severity: SeverityInfo,
					Message:  "Test info",
				},
			},
			expectedErrors: 0,
			expectedWarn:   0,
			expectedInfo:   1,
			expectedPassed: true,
		},
		{
			name: "mixed findings",
			findings: []Finding{
				{
					RuleID:   "CCG001",
					Category: CategoryExecCommand,
					Severity: SeverityError,
					Message:  "Error 1",
				},
				{
					RuleID:   "CCG002",
					Category: CategoryCGO,
					Severity: SeverityWarning,
					Message:  "Warning 1",
				},
				{
					RuleID:   "CCG003",
					Category: CategoryDynamicLinking,
					Severity: SeverityInfo,
					Message:  "Info 1",
				},
				{
					RuleID:   "CCG004",
					Category: CategoryDockerfile,
					Severity: SeverityError,
					Message:  "Error 2",
				},
			},
			expectedErrors: 2,
			expectedWarn:   1,
			expectedInfo:   1,
			expectedPassed: false,
		},
		{
			name: "multiple categories",
			findings: []Finding{
				{
					RuleID:   "CCG001",
					Category: CategoryExecCommand,
					Severity: SeverityWarning,
					Message:  "Exec warning",
				},
				{
					RuleID:   "CCG010",
					Category: CategoryCGO,
					Severity: SeverityWarning,
					Message:  "CGO warning",
				},
				{
					RuleID:   "CCG020",
					Category: CategoryDynamicLinking,
					Severity: SeverityWarning,
					Message:  "Linking warning",
				},
			},
			expectedErrors: 0,
			expectedWarn:   3,
			expectedInfo:   0,
			expectedPassed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := NewEngine()
			result := engine.Evaluate(tt.findings)

			if result.Summary.ErrorCount != tt.expectedErrors {
				t.Errorf("ErrorCount = %d, want %d", result.Summary.ErrorCount, tt.expectedErrors)
			}
			if result.Summary.WarningCount != tt.expectedWarn {
				t.Errorf("WarningCount = %d, want %d", result.Summary.WarningCount, tt.expectedWarn)
			}
			if result.Summary.InfoCount != tt.expectedInfo {
				t.Errorf("InfoCount = %d, want %d", result.Summary.InfoCount, tt.expectedInfo)
			}
			if result.Passed != tt.expectedPassed {
				t.Errorf("Passed = %v, want %v", result.Passed, tt.expectedPassed)
			}
			if result.Summary.TotalFindings != len(tt.findings) {
				t.Errorf("TotalFindings = %d, want %d", result.Summary.TotalFindings, len(tt.findings))
			}
		})
	}
}

func TestEngineCategoryCount(t *testing.T) {
	findings := []Finding{
		{Category: CategoryExecCommand, Severity: SeverityWarning},
		{Category: CategoryExecCommand, Severity: SeverityWarning},
		{Category: CategoryCGO, Severity: SeverityError},
		{Category: CategoryDockerfile, Severity: SeverityInfo},
		{Category: CategoryDockerfile, Severity: SeverityInfo},
		{Category: CategoryDockerfile, Severity: SeverityInfo},
	}

	engine := NewEngine()
	result := engine.Evaluate(findings)

	expectedCounts := map[Category]int{
		CategoryExecCommand: 2,
		CategoryCGO:         1,
		CategoryDockerfile:  3,
	}

	for cat, expected := range expectedCounts {
		if result.Summary.ByCategory[cat] != expected {
			t.Errorf("ByCategory[%s] = %d, want %d", cat, result.Summary.ByCategory[cat], expected)
		}
	}
}

func TestResultHasErrors(t *testing.T) {
	tests := []struct {
		name       string
		errorCount int
		expected   bool
	}{
		{"no errors", 0, false},
		{"one error", 1, true},
		{"multiple errors", 5, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &Result{
				Summary: Summary{
					ErrorCount: tt.errorCount,
				},
			}
			if result.HasErrors() != tt.expected {
				t.Errorf("HasErrors() = %v, want %v", result.HasErrors(), tt.expected)
			}
		})
	}
}

func TestResultHasWarnings(t *testing.T) {
	tests := []struct {
		name         string
		warningCount int
		expected     bool
	}{
		{"no warnings", 0, false},
		{"one warning", 1, true},
		{"multiple warnings", 5, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &Result{
				Summary: Summary{
					WarningCount: tt.warningCount,
				},
			}
			if result.HasWarnings() != tt.expected {
				t.Errorf("HasWarnings() = %v, want %v", result.HasWarnings(), tt.expected)
			}
		})
	}
}

func TestEngineGetRule(t *testing.T) {
	engine := NewEngine()

	// Test existing rule
	rule := engine.GetRule("CCG001")
	if rule == nil {
		t.Error("GetRule(CCG001) returned nil for existing rule")
	}
	if rule != nil && rule.ID != "CCG001" {
		t.Errorf("GetRule(CCG001).ID = %s, want CCG001", rule.ID)
	}

	// Test non-existing rule
	rule = engine.GetRule("NONEXISTENT")
	if rule != nil {
		t.Error("GetRule(NONEXISTENT) should return nil for non-existing rule")
	}
}

func TestEngineEnableDisableRule(t *testing.T) {
	engine := NewEngine()

	// Verify rule is enabled by default
	if !engine.IsRuleEnabled("CCG001") {
		t.Error("CCG001 should be enabled by default")
	}

	// Disable rule
	engine.DisableRule("CCG001")
	if engine.IsRuleEnabled("CCG001") {
		t.Error("CCG001 should be disabled after DisableRule()")
	}

	// Enable rule
	engine.EnableRule("CCG001")
	if !engine.IsRuleEnabled("CCG001") {
		t.Error("CCG001 should be enabled after EnableRule()")
	}

	// Test non-existing rule
	engine.DisableRule("NONEXISTENT") // Should not panic
	if engine.IsRuleEnabled("NONEXISTENT") {
		t.Error("IsRuleEnabled(NONEXISTENT) should return false")
	}
}

func TestEngineListRules(t *testing.T) {
	engine := NewEngine()
	rules := engine.ListRules()

	if len(rules) == 0 {
		t.Error("ListRules() returned empty list")
	}

	// Verify all rules have required fields
	for _, rule := range rules {
		if rule.ID == "" {
			t.Error("Rule has empty ID")
		}
		if rule.Name == "" {
			t.Errorf("Rule %s has empty Name", rule.ID)
		}
		if rule.Description == "" {
			t.Errorf("Rule %s has empty Description", rule.ID)
		}
		if rule.Severity == "" {
			t.Errorf("Rule %s has empty Severity", rule.ID)
		}
		if rule.Category == "" {
			t.Errorf("Rule %s has empty Category", rule.ID)
		}
	}

	// Verify specific rules exist
	expectedRules := []string{"CCG001", "CCG010", "CCG020", "CCG030", "CCG040", "CCG050"}
	ruleMap := make(map[string]bool)
	for _, rule := range rules {
		ruleMap[rule.ID] = true
	}

	for _, expectedID := range expectedRules {
		if !ruleMap[expectedID] {
			t.Errorf("Expected rule %s not found", expectedID)
		}
	}
}

func TestSeverityConstants(t *testing.T) {
	// Verify severity constants are defined correctly
	if SeverityError != "error" {
		t.Errorf("SeverityError = %s, want error", SeverityError)
	}
	if SeverityWarning != "warning" {
		t.Errorf("SeverityWarning = %s, want warning", SeverityWarning)
	}
	if SeverityInfo != "info" {
		t.Errorf("SeverityInfo = %s, want info", SeverityInfo)
	}
}

func TestCategoryConstants(t *testing.T) {
	// Verify category constants are defined correctly
	expectedCategories := map[Category]string{
		CategoryExecCommand:    "exec_command",
		CategoryCGO:            "cgo",
		CategoryDynamicLinking: "dynamic_linking",
		CategoryDockerfile:     "dockerfile",
		CategoryBaseImage:      "base_image",
		CategoryMultiStage:     "multi_stage",
	}

	for cat, expected := range expectedCategories {
		if string(cat) != expected {
			t.Errorf("Category %v = %s, want %s", cat, string(cat), expected)
		}
	}
}

func TestFindingLocation(t *testing.T) {
	finding := Finding{
		RuleID:   "CCG001",
		Category: CategoryExecCommand,
		Severity: SeverityWarning,
		Message:  "Test finding",
		Location: Location{
			File:   "test.go",
			Line:   42,
			Column: 10,
			Stage:  "builder",
		},
	}

	if finding.Location.File != "test.go" {
		t.Errorf("Location.File = %s, want test.go", finding.Location.File)
	}
	if finding.Location.Line != 42 {
		t.Errorf("Location.Line = %d, want 42", finding.Location.Line)
	}
	if finding.Location.Column != 10 {
		t.Errorf("Location.Column = %d, want 10", finding.Location.Column)
	}
	if finding.Location.Stage != "builder" {
		t.Errorf("Location.Stage = %s, want builder", finding.Location.Stage)
	}
}

func TestFindingDetails(t *testing.T) {
	finding := Finding{
		RuleID:   "CCG001",
		Category: CategoryExecCommand,
		Severity: SeverityWarning,
		Message:  "Test finding",
		Details: map[string]interface{}{
			"command": "ls",
			"args":    []string{"-la"},
		},
		Suggestion: "Use pure Go alternative",
	}

	if finding.Details["command"] != "ls" {
		t.Errorf("Details[command] = %v, want ls", finding.Details["command"])
	}
	if finding.Suggestion != "Use pure Go alternative" {
		t.Errorf("Suggestion = %s, want 'Use pure Go alternative'", finding.Suggestion)
	}
}

package correlator

import (
	"testing"

	"github.com/Jonsy13/go-runtime-compat/internal/rules"
)

func TestExtractDependencies(t *testing.T) {
	c := NewCorrelator()

	tests := []struct {
		name     string
		findings []rules.Finding
		wantDeps int
		wantType DependencyType
	}{
		{
			name:     "empty findings",
			findings: []rules.Finding{},
			wantDeps: 0,
		},
		{
			name: "shell command",
			findings: []rules.Finding{
				{
					RuleID:   "CCG002",
					Category: rules.CategoryExecCommand,
					Details:  map[string]interface{}{"command": "bash"},
				},
			},
			wantDeps: 1,
			wantType: DepShellCommand,
		},
		{
			name: "system binary",
			findings: []rules.Finding{
				{
					RuleID:   "CCG003",
					Category: rules.CategoryExecCommand,
					Details:  map[string]interface{}{"command": "curl"},
				},
			},
			wantDeps: 1,
			wantType: DepSystemBinary,
		},
		{
			name: "CGO import",
			findings: []rules.Finding{
				{
					RuleID:   "CCG011",
					Category: rules.CategoryCGO,
					Details:  map[string]interface{}{"import": "C"},
				},
			},
			wantDeps: 1,
			wantType: DepCGO,
		},
		{
			name: "multiple dependencies",
			findings: []rules.Finding{
				{
					RuleID:   "CCG002",
					Category: rules.CategoryExecCommand,
					Details:  map[string]interface{}{"command": "bash"},
				},
				{
					RuleID:   "CCG003",
					Category: rules.CategoryExecCommand,
					Details:  map[string]interface{}{"command": "curl"},
				},
				{
					RuleID:   "CCG011",
					Category: rules.CategoryCGO,
					Details:  map[string]interface{}{"import": "C"},
				},
			},
			wantDeps: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps := c.ExtractDependencies(tt.findings)
			if len(deps) != tt.wantDeps {
				t.Errorf("ExtractDependencies() got %d deps, want %d", len(deps), tt.wantDeps)
			}
			if tt.wantDeps > 0 && tt.wantType != "" && deps[0].Type != tt.wantType {
				t.Errorf("ExtractDependencies() got type %s, want %s", deps[0].Type, tt.wantType)
			}
		})
	}
}

func TestExtractCapabilities(t *testing.T) {
	c := NewCorrelator()

	tests := []struct {
		name     string
		findings []rules.Finding
		wantCap  DockerfileCapability
	}{
		{
			name:     "empty findings",
			findings: []rules.Finding{},
			wantCap:  DockerfileCapability{},
		},
		{
			name: "scratch image",
			findings: []rules.Finding{
				{
					RuleID:   "CCG035",
					Category: rules.CategoryDockerfile,
					Details:  map[string]interface{}{"base_image": "scratch", "is_final_stage": true},
				},
				{
					RuleID:   "CCG030",
					Category: rules.CategoryDockerfile,
					Details:  map[string]interface{}{"base_image": "scratch", "is_final_stage": true},
				},
			},
			wantCap: DockerfileCapability{
				IsMinimalImage: true,
				HasShell:       false,
				HasGlibc:       false,
				FinalBaseImage: "scratch",
			},
		},
		{
			name: "alpine image",
			findings: []rules.Finding{
				{
					RuleID:   "CCG035",
					Category: rules.CategoryDockerfile,
					Details:  map[string]interface{}{"base_image": "alpine:latest", "is_final_stage": true},
				},
				{
					RuleID:   "CCG032",
					Category: rules.CategoryDockerfile,
					Details:  map[string]interface{}{"base_image": "alpine:latest", "is_final_stage": true},
				},
			},
			wantCap: DockerfileCapability{
				IsAlpineImage:  true,
				HasShell:       true,
				HasMusl:        true,
				HasGlibc:       false,
				FinalBaseImage: "alpine:latest",
			},
		},
		{
			name: "distroless image",
			findings: []rules.Finding{
				{
					RuleID:   "CCG035",
					Category: rules.CategoryDockerfile,
					Details:  map[string]interface{}{"base_image": "gcr.io/distroless/static", "is_final_stage": true},
				},
				{
					RuleID:   "CCG031",
					Category: rules.CategoryDockerfile,
					Details:  map[string]interface{}{"base_image": "gcr.io/distroless/static", "is_final_stage": true},
				},
			},
			wantCap: DockerfileCapability{
				IsMinimalImage: true,
				HasShell:       false,
				HasGlibc:       true,
				FinalBaseImage: "gcr.io/distroless/static",
			},
		},
		{
			name: "UBI image",
			findings: []rules.Finding{
				{
					RuleID:   "CCG035",
					Category: rules.CategoryDockerfile,
					Details:  map[string]interface{}{"base_image": "registry.access.redhat.com/ubi9/ubi:latest", "is_final_stage": true},
				},
			},
			wantCap: DockerfileCapability{
				IsMinimalImage: false,
				HasShell:       true,
				HasGlibc:       true,
				FinalBaseImage: "registry.access.redhat.com/ubi9/ubi:latest",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cap := c.ExtractCapabilities(tt.findings)
			if cap.IsMinimalImage != tt.wantCap.IsMinimalImage {
				t.Errorf("IsMinimalImage got %v, want %v", cap.IsMinimalImage, tt.wantCap.IsMinimalImage)
			}
			if cap.HasShell != tt.wantCap.HasShell {
				t.Errorf("HasShell got %v, want %v", cap.HasShell, tt.wantCap.HasShell)
			}
			if cap.IsAlpineImage != tt.wantCap.IsAlpineImage {
				t.Errorf("IsAlpineImage got %v, want %v", cap.IsAlpineImage, tt.wantCap.IsAlpineImage)
			}
		})
	}
}

func TestCorrelate(t *testing.T) {
	c := NewCorrelator()

	tests := []struct {
		name         string
		deps         []Dependency
		cap          DockerfileCapability
		wantFindings int
		wantRuleID   string
	}{
		{
			name:         "no dependencies",
			deps:         []Dependency{},
			cap:          DockerfileCapability{},
			wantFindings: 0,
		},
		{
			name: "shell command with scratch",
			deps: []Dependency{
				{Type: DepShellCommand, Name: "bash", Location: rules.Location{File: "main.go", Line: 10}},
			},
			cap: DockerfileCapability{
				IsMinimalImage: true,
				HasShell:       false,
				FinalBaseImage: "scratch",
			},
			wantFindings: 1,
			wantRuleID:   "CCG100",
		},
		{
			name: "shell command with alpine (has shell)",
			deps: []Dependency{
				{Type: DepShellCommand, Name: "sh", Location: rules.Location{File: "main.go", Line: 10}},
			},
			cap: DockerfileCapability{
				IsAlpineImage:  true,
				HasShell:       true,
				FinalBaseImage: "alpine:latest",
			},
			wantFindings: 0,
		},
		{
			name: "curl with alpine (not available)",
			deps: []Dependency{
				{Type: DepSystemBinary, Name: "curl", Location: rules.Location{File: "main.go", Line: 10}},
			},
			cap: DockerfileCapability{
				IsAlpineImage:     true,
				HasShell:          true,
				FinalBaseImage:    "alpine:latest",
				AvailableBinaries: []string{"sh", "ls", "cat"},
			},
			wantFindings: 1,
			wantRuleID:   "CCG101",
		},
		{
			name: "CGO with scratch (no glibc)",
			deps: []Dependency{
				{Type: DepCGO, Name: "CGO", Location: rules.Location{File: "main.go", Line: 10}},
			},
			cap: DockerfileCapability{
				IsMinimalImage: true,
				HasGlibc:       false,
				CGODisabled:    false,
				FinalBaseImage: "scratch",
			},
			wantFindings: 1,
			wantRuleID:   "CCG103",
		},
		{
			name: "CGO with alpine (musl mismatch)",
			deps: []Dependency{
				{Type: DepCGO, Name: "CGO", Location: rules.Location{File: "main.go", Line: 10}},
			},
			cap: DockerfileCapability{
				IsAlpineImage:  true,
				HasMusl:        true,
				HasGlibc:       false,
				CGODisabled:    false,
				FinalBaseImage: "alpine:latest",
			},
			wantFindings: 1,
			wantRuleID:   "CCG104",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := c.Correlate(tt.deps, tt.cap)
			if len(findings) != tt.wantFindings {
				t.Errorf("Correlate() got %d findings, want %d", len(findings), tt.wantFindings)
			}
			if tt.wantFindings > 0 && findings[0].RuleID != tt.wantRuleID {
				t.Errorf("Correlate() got rule ID %s, want %s", findings[0].RuleID, tt.wantRuleID)
			}
		})
	}
}

func TestCorrelateAll(t *testing.T) {
	c := NewCorrelator()

	goFindings := []rules.Finding{
		{
			RuleID:   "CCG002",
			Category: rules.CategoryExecCommand,
			Details:  map[string]interface{}{"command": "bash"},
			Location: rules.Location{File: "main.go", Line: 10},
		},
	}

	dockerfileFindings := []rules.Finding{
		{
			RuleID:   "CCG035",
			Category: rules.CategoryDockerfile,
			Details:  map[string]interface{}{"base_image": "scratch", "is_final_stage": true},
		},
		{
			RuleID:   "CCG030",
			Category: rules.CategoryDockerfile,
			Details:  map[string]interface{}{"base_image": "scratch", "is_final_stage": true},
		},
	}

	result := c.CorrelateAll(goFindings, dockerfileFindings)

	if len(result.Dependencies) != 1 {
		t.Errorf("CorrelateAll() got %d dependencies, want 1", len(result.Dependencies))
	}

	if !result.Capabilities.IsMinimalImage {
		t.Error("CorrelateAll() expected IsMinimalImage to be true")
	}

	// Should have at least one correlation finding (shell command with scratch)
	if len(result.Findings) == 0 {
		t.Error("CorrelateAll() expected at least one correlation finding")
	}
}

func TestIsBinaryAvailable(t *testing.T) {
	c := NewCorrelator()

	tests := []struct {
		name   string
		binary string
		cap    DockerfileCapability
		want   bool
	}{
		{
			name:   "ls in alpine",
			binary: "ls",
			cap: DockerfileCapability{
				IsAlpineImage:     true,
				AvailableBinaries: []string{"sh", "ls", "cat", "grep"},
			},
			want: true,
		},
		{
			name:   "curl in alpine (not available)",
			binary: "curl",
			cap: DockerfileCapability{
				IsAlpineImage:     true,
				AvailableBinaries: []string{"sh", "ls", "cat", "grep"},
			},
			want: false,
		},
		{
			name:   "bash in alpine (not available)",
			binary: "bash",
			cap: DockerfileCapability{
				IsAlpineImage:     true,
				AvailableBinaries: []string{"sh", "ls", "cat", "grep"},
			},
			want: false,
		},
		{
			name:   "any binary in scratch",
			binary: "ls",
			cap: DockerfileCapability{
				IsMinimalImage:    true,
				HasShell:          false,
				AvailableBinaries: []string{},
			},
			want: false,
		},
		{
			name:   "binary with path prefix",
			binary: "/usr/bin/ls",
			cap: DockerfileCapability{
				IsAlpineImage:     true,
				AvailableBinaries: []string{"sh", "ls", "cat"},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := c.isBinaryAvailable(tt.binary, tt.cap)
			if got != tt.want {
				t.Errorf("isBinaryAvailable(%s) = %v, want %v", tt.binary, got, tt.want)
			}
		})
	}
}

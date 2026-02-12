# AI Agent Instructions

This file provides guidance for AI coding assistants (Claude, GPT, Copilot, Cursor, etc.) working with the `go-runtime-compat` codebase.

## Project Overview

`go-runtime-compat` is a static analyzer that detects container compatibility issues in Go projects. It helps ensure Go applications run correctly in containerized environments like `scratch`, `distroless`, and `alpine` images.

## Key Commands

```bash
# Analyze a Go project
go-runtime-compat analyze --project ./path/to/project

# Analyze with Dockerfile
go-runtime-compat analyze --project . --dockerfile ./Dockerfile

# JSON output (recommended for programmatic use)
go-runtime-compat analyze --project . --output json

# Strict mode (exit non-zero on warnings)
go-runtime-compat analyze --project . --strict

# List all rules
go-runtime-compat rules --output json
```

## Project Structure

```
go-runtime-compat/
├── main.go                          # CLI entry point
├── go.mod                           # Go module (github.com/Jonsy13/go-runtime-compat)
└── internal/
    ├── analyzer/
    │   └── go_analyzer.go           # Go AST analysis for exec.Command, CGO
    ├── cli/
    │   └── root.go                  # Cobra CLI commands
    ├── correlator/
    │   └── correlator.go            # Cross-references code with Dockerfile
    ├── docker/
    │   ├── dockerfile_analyzer.go   # Dockerfile parsing
    │   └── image_inspector.go       # Docker image inspection via ldd
    ├── report/
    │   └── reporter.go              # Output formatting (CLI, JSON, CSV)
    └── rules/
        ├── engine.go                # Rules evaluation engine
        └── types.go                 # Finding, Rule, Result types
```

## Rule IDs

Rules use the `CCG` prefix:

| Range | Category |
|-------|----------|
| CCG001-009 | exec.Command usage |
| CCG010-019 | CGO dependencies |
| CCG020-029 | Dynamic linking |
| CCG030-039 | Dockerfile base images |
| CCG040-049 | Multi-stage builds |
| CCG100-109 | Correlation issues (code + Dockerfile) |

## Working with This Codebase

### Adding a New Rule

1. Define the rule in `internal/rules/engine.go` in the `initializeRules()` function
2. Add detection logic in the appropriate analyzer:
   - Go code issues: `internal/analyzer/go_analyzer.go`
   - Dockerfile issues: `internal/docker/dockerfile_analyzer.go`
   - Correlation issues: `internal/correlator/correlator.go`
3. Create a `rules.Finding` with the new rule ID

### Key Types

```go
// internal/rules/types.go

type Finding struct {
    RuleID     string
    Category   Category
    Severity   Severity  // Error, Warning, Info
    Message    string
    Location   string
    Suggestion string
    Details    map[string]interface{}
}

type Severity string
const (
    SeverityError   Severity = "error"
    SeverityWarning Severity = "warning"
    SeverityInfo    Severity = "info"
)
```

### Running Tests

```bash
go test ./...
go test ./internal/rules/...
go test ./internal/correlator/...
```

### Building

```bash
go build .
./go-runtime-compat version
```

## Common Issues to Detect

When analyzing Go code for container compatibility:

1. **exec.Command calls** - External binaries may not exist in minimal containers
2. **CGO imports** (`import "C"`) - Requires glibc, fails on scratch/alpine
3. **Shell commands** - `bash`, `sh` not available in scratch/distroless
4. **System binaries** - `curl`, `wget`, `git` not in minimal images

## JSON Output Schema

```json
{
  "findings": [
    {
      "rule_id": "string",
      "category": "string",
      "severity": "error|warning|info",
      "message": "string",
      "location": "file:line",
      "suggestion": "string",
      "details": {}
    }
  ],
  "summary": {
    "total_findings": 0,
    "error_count": 0,
    "warning_count": 0,
    "info_count": 0,
    "passed": true
  }
}
```

## Integration Tips

- Always use `--output json` when parsing results programmatically
- Check `summary.passed` to determine if the analysis succeeded
- Filter findings by `severity` to prioritize fixes
- Use `--strict` in CI/CD to fail on warnings

## Do Not

- Modify rule IDs (CCG prefix is intentional)
- Remove test files without explicit instruction
- Change the module path in go.mod

<div align="center">

# go-runtime-compat

**Catch container runtime issues before they catch you**

[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![Go Report Card](https://goreportcard.com/badge/github.com/Jonsy13/go-runtime-compat)](https://goreportcard.com/report/github.com/Jonsy13/go-runtime-compat)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[Features](#features) | [Installation](#installation) | [Usage](#usage) | [Rules](#detection-rules) | [CI/CD](#cicd-integration)

</div>

---

## The Problem

Building Go applications for containers seems straightforward until runtime failures occur:

- Binary crashes with `exec format error` in scratch images
- `exec.Command("curl", ...)` fails silently in distroless containers  
- CGO binaries segfault on Alpine due to musl/glibc mismatch
- Shell scripts that worked in development break in production

**go-runtime-compat** statically analyzes your Go code and Dockerfiles to detect these issues *before* deployment.

## Features

| Feature | Description |
|---------|-------------|
| **Go Code Analysis** | Detects `exec.Command` usage, CGO dependencies, and system binary calls |
| **Dockerfile Analysis** | Analyzes multi-stage builds, base images, and build configurations |
| **Image Inspection** | Checks for dynamic linking issues using `ldd` |
| **Correlation Engine** | Cross-references code dependencies with container capabilities |
| **Multiple Outputs** | CLI (human-readable), JSON, and CSV formats |

## Installation

### Quick Install

```bash
go install github.com/Jonsy13/go-runtime-compat@latest
```

### Build from Source

```bash
git clone https://github.com/Jonsy13/go-runtime-compat.git
cd go-runtime-compat
go build .
```

## Usage

### Basic Commands

```bash
# Analyze Go source code
go-runtime-compat analyze --project ./myapp

# Analyze a Dockerfile
go-runtime-compat analyze --dockerfile ./Dockerfile

# Analyze a built Docker image
go-runtime-compat analyze --image myapp:latest

# Full analysis (recommended)
go-runtime-compat analyze --project ./myapp --dockerfile ./Dockerfile

# Strict mode - exit non-zero on warnings
go-runtime-compat analyze --project . --dockerfile ./Dockerfile --strict
```

### Output Formats

```bash
# Human-readable CLI output (default)
go-runtime-compat analyze --project . --output cli

# JSON for programmatic processing
go-runtime-compat analyze --project . --output json

# CSV for spreadsheet analysis
go-runtime-compat analyze --project . --output csv
```

### List Available Rules

```bash
go-runtime-compat rules
go-runtime-compat rules --output json
```

## Detection Rules

### Go Code Issues

| Rule | Severity | Description |
|------|----------|-------------|
| `CCG001` | Warning | External binary execution via `exec.Command` |
| `CCG002` | Warning | Shell command execution (`sh`, `bash`, etc.) |
| `CCG003` | Warning | System binary dependencies |
| `CCG004` | Info | Binary usage summary across codebase |
| `CCG005` | Warning | Dynamic/unresolved command in `exec.Command` |
| `CCG010` | Warning | `CGO_ENABLED=1` detected |
| `CCG011` | Error | Direct CGO import (`import "C"`) |

### Dockerfile Issues

| Rule | Severity | Description |
|------|----------|-------------|
| `CCG030` | Info | Scratch base image - requires static linking |
| `CCG031` | Info | Distroless base image - no shell available |
| `CCG032` | Warning | Alpine base image - uses musl instead of glibc |
| `CCG033` | Warning | Go build without `CGO_ENABLED=0` in minimal image |
| `CCG040` | Info | Multi-stage build detected |
| `CCG041` | Warning | Build/runtime stage CGO mismatch |

### Correlation Issues

| Rule | Severity | Description |
|------|----------|-------------|
| `CCG100` | Error | Shell command used but base image has no shell |
| `CCG101` | Error | Required binary unavailable in base image |
| `CCG102` | Warning | `exec.Command` with minimal base image |
| `CCG103` | Error | CGO detected but base image lacks glibc |
| `CCG104` | Error | CGO binary with Alpine (musl/glibc mismatch) |

## Example Output

```
╔══════════════════════════════════════════════════════════════════╗
║              go-runtime-compat Analysis Report                   ║
╚══════════════════════════════════════════════════════════════════╝

📊 Summary
──────────────────────────────────────────────────────────────────
  Total Findings: 3
  ❌ Errors:      1
  ⚠️  Warnings:    2
  ℹ️  Info:        0

❌ Status: FAILED

📋 Findings by Category
──────────────────────────────────────────────────────────────────

  📁 Correlation (1 finding)
  ────────────────────────────────────────────────────────────
  ❌ [CCG100] Shell command 'bash' used but Dockerfile uses scratch which has no shell
     📍 Location: main.go:42
     📄 Code: exec.Command("bash", "-c", "echo hello")
     💡 Suggestion: Either use a base image with a shell or remove shell command usage

  📁 Exec Command (2 findings)
  ────────────────────────────────────────────────────────────
  ⚠️  [CCG002] Shell 'bash' executed - verify shell is available in your container
     📍 Location: main.go:42
     💡 Suggestion: Ensure your base image has a shell
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Go Runtime Compatibility Check

on: [push, pull_request]

jobs:
  compat-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.25'
      
      - name: Install go-runtime-compat
        run: go install github.com/Jonsy13/go-runtime-compat@latest
      
      - name: Run compatibility check
        run: go-runtime-compat analyze --project . --dockerfile ./Dockerfile --strict
```

### GitLab CI

```yaml
container-compatibility:
  image: golang:1.25
  stage: test
  script:
    - go install github.com/Jonsy13/go-runtime-compat@latest
    - go-runtime-compat analyze --project . --dockerfile ./Dockerfile --output json > compat-report.json
  artifacts:
    paths:
      - compat-report.json
    reports:
      codequality: compat-report.json
```

### Pre-commit Hook

```bash
#!/bin/sh
# .git/hooks/pre-commit

if command -v go-runtime-compat &> /dev/null; then
    go-runtime-compat analyze --project . --dockerfile ./Dockerfile --strict
fi
```

## Best Practices

### Scratch / Distroless Images

```dockerfile
FROM golang:1.25 AS builder
WORKDIR /app
COPY . .

# Disable CGO for static binary
ENV CGO_ENABLED=0

# Build with optimizations
RUN go build -ldflags="-s -w" -o /app/server .

FROM scratch
COPY --from=builder /app/server /server
ENTRYPOINT ["/server"]
```

**Key points:**
- Always set `CGO_ENABLED=0`
- Avoid `exec.Command` calls - use pure Go alternatives
- No shell available - use direct binary entrypoint

### Alpine Images

```dockerfile
FROM golang:1.25-alpine AS builder
WORKDIR /app

# Option 1: Disable CGO (recommended)
ENV CGO_ENABLED=0
RUN go build -o /app/server .

# Option 2: Build with musl (if CGO required)
# RUN apk add --no-cache gcc musl-dev
# RUN go build -o /app/server .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/server /server
ENTRYPOINT ["/server"]
```

**Key points:**
- Alpine uses musl libc, not glibc
- CGO binaries built with glibc will fail
- Either disable CGO or compile against musl

## Architecture

```
go-runtime-compat/
├── main.go                          # CLI entry point
└── internal/
    ├── analyzer/
    │   └── go_analyzer.go           # Go AST analysis
    ├── cli/
    │   └── root.go                  # Cobra command definitions
    ├── correlator/
    │   └── correlator.go            # Cross-reference engine
    ├── docker/
    │   ├── dockerfile_analyzer.go   # Dockerfile parsing
    │   └── image_inspector.go       # Docker image inspection
    ├── report/
    │   └── reporter.go              # Output formatting
    └── rules/
        ├── engine.go                # Rules evaluation
        └── types.go                 # Type definitions
```

## Contributing

Contributions are welcome! Here's how to get started:

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/my-feature`
3. **Commit** your changes: `git commit -m 'Add my feature'`
4. **Push** to the branch: `git push origin feature/my-feature`
5. **Open** a Pull Request

### Development

```bash
# Run tests
go test ./...

# Build
go build .

# Test against sample project
./go-runtime-compat analyze --project ./testdata/sample --dockerfile ./testdata/Dockerfile
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**Built with [Cobra](https://github.com/spf13/cobra)**

</div>

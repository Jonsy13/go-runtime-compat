// Package analyzer provides static analysis capabilities for Go source code.
package analyzer

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Jonsy13/go-runtime-compat/internal/rules"
)

// GoAnalyzer analyzes Go source code for container compatibility issues.
type GoAnalyzer struct {
	fset             *token.FileSet
	detectedBinaries map[string][]BinaryUsage // Map of binary name to usages
}

// BinaryUsage represents a usage of an external binary in the code.
type BinaryUsage struct {
	Binary        string
	Args          []string
	File          string
	Line          int
	Column        int
	IsShell       bool
	ShellCmd      string   // The full shell command if this binary was found inside a shell -c command
	ShellBinaries []string // Other binaries used in the same shell command
}

// NewGoAnalyzer creates a new Go analyzer.
func NewGoAnalyzer() *GoAnalyzer {
	return &GoAnalyzer{
		fset:             token.NewFileSet(),
		detectedBinaries: make(map[string][]BinaryUsage),
	}
}

// GetDetectedBinaries returns all binaries detected during analysis.
func (a *GoAnalyzer) GetDetectedBinaries() map[string][]BinaryUsage {
	return a.detectedBinaries
}

// GetBinarySummary returns a summary of all detected binaries with all their usage locations clubbed together.
func (a *GoAnalyzer) GetBinarySummary() []rules.Finding {
	var findings []rules.Finding

	// Sort binaries for consistent output
	var binaries []string
	for binary := range a.detectedBinaries {
		binaries = append(binaries, binary)
	}
	sort.Strings(binaries)

	for _, binary := range binaries {
		usages := a.detectedBinaries[binary]
		if len(usages) == 0 {
			continue
		}

		// Check if it's a shell
		isShell := usages[0].IsShell

		// Build detailed location info with file:line and context
		var locationDetails []map[string]interface{}
		var messageLines []string

		for _, u := range usages {
			locStr := fmt.Sprintf("%s:%d", u.File, u.Line)

			// Build the display line with context
			displayLine := locStr
			if isShell && len(u.ShellBinaries) > 0 {
				// For shells, show what binaries are used in the command
				displayLine += fmt.Sprintf(" → uses: %s", strings.Join(u.ShellBinaries, ", "))
			} else if u.ShellCmd != "" {
				// For binaries found inside shell commands, show the shell command
				shellCmdDisplay := u.ShellCmd
				if len(shellCmdDisplay) > 50 {
					shellCmdDisplay = shellCmdDisplay[:47] + "..."
				}
				displayLine += fmt.Sprintf(" (in shell: %s)", shellCmdDisplay)
			} else if len(u.Args) > 0 {
				// For direct exec.Command calls, show args
				argsDisplay := strings.Join(u.Args, " ")
				if len(argsDisplay) > 30 {
					argsDisplay = argsDisplay[:27] + "..."
				}
				displayLine += fmt.Sprintf(" [%s]", argsDisplay)
			}
			messageLines = append(messageLines, displayLine)

			locDetail := map[string]interface{}{
				"file": u.File,
				"line": u.Line,
			}
			if len(u.Args) > 0 {
				locDetail["args"] = u.Args
			}
			if u.ShellCmd != "" {
				locDetail["shell_cmd"] = u.ShellCmd
			}
			if len(u.ShellBinaries) > 0 {
				locDetail["shell_binaries"] = u.ShellBinaries
			}
			locationDetails = append(locationDetails, locDetail)
		}

		severity := rules.SeverityInfo
		var message string
		if isShell {
			message = fmt.Sprintf("Shell '%s' is used in %d location(s):", binary, len(usages))
		} else {
			message = fmt.Sprintf("Binary '%s' is used in %d location(s):", binary, len(usages))
		}

		// Add location summary to message
		for i, line := range messageLines {
			if i < 5 { // Show first 5 locations in message
				message += fmt.Sprintf("\n     • %s", line)
			}
		}
		if len(messageLines) > 5 {
			message += fmt.Sprintf("\n     ... and %d more", len(messageLines)-5)
		}

		// Collect all location strings for details
		locationStrings := make([]string, len(usages))
		for i, u := range usages {
			locationStrings[i] = fmt.Sprintf("%s:%d", u.File, u.Line)
		}

		findings = append(findings, rules.Finding{
			RuleID:   "CCG004",
			Category: rules.CategoryExecCommand,
			Severity: severity,
			Message:  message,
			Location: rules.Location{
				File: usages[0].File,
				Line: usages[0].Line,
			},
			Details: map[string]interface{}{
				"binary":           binary,
				"is_shell":         isShell,
				"count":            len(usages),
				"locations":        locationStrings,
				"location_details": locationDetails,
			},
			Suggestion: fmt.Sprintf("Ensure '%s' is available in your container image", binary),
		})
	}

	return findings
}

// Analyze analyzes Go source code in the given directory.
func (a *GoAnalyzer) Analyze(projectPath string) ([]rules.Finding, error) {
	var findings []rules.Finding

	err := filepath.Walk(projectPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip vendor and hidden directories
		if info.IsDir() {
			if info.Name() == "vendor" || strings.HasPrefix(info.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}

		// Only process Go files
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		fileFindings, err := a.analyzeFile(path)
		if err != nil {
			// Log error but continue with other files
			return nil
		}
		findings = append(findings, fileFindings...)
		return nil
	})

	if err != nil {
		return nil, err
	}

	return findings, nil
}

// analyzeFile analyzes a single Go source file.
func (a *GoAnalyzer) analyzeFile(filePath string) ([]rules.Finding, error) {
	var findings []rules.Finding

	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	file, err := parser.ParseFile(a.fset, filePath, src, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	// Check for CGO imports
	cgoFindings := a.checkCGOImports(file, filePath)
	findings = append(findings, cgoFindings...)

	// Check for exec.Command usage
	execFindings := a.checkExecCommand(file, filePath)
	findings = append(findings, execFindings...)

	return findings, nil
}

// checkCGOImports checks for CGO imports in the file.
func (a *GoAnalyzer) checkCGOImports(file *ast.File, filePath string) []rules.Finding {
	var findings []rules.Finding

	for _, imp := range file.Imports {
		if imp.Path.Value == `"C"` {
			pos := a.fset.Position(imp.Pos())
			findings = append(findings, rules.Finding{
				RuleID:   "CCG011",
				Category: rules.CategoryCGO,
				Severity: rules.SeverityError,
				Message:  "CGO import detected - binary will require glibc and may not work in Alpine/scratch images",
				Location: rules.Location{
					File:   filePath,
					Line:   pos.Line,
					Column: pos.Column,
				},
				Details: map[string]interface{}{
					"import": "C",
				},
				Suggestion: "Consider using pure Go alternatives or ensure your container has glibc. Set CGO_ENABLED=0 if CGO is not actually needed.",
			})
		}
	}

	return findings
}

// checkExecCommand checks for exec.Command usage in the file.
func (a *GoAnalyzer) checkExecCommand(file *ast.File, filePath string) []rules.Finding {
	var findings []rules.Finding

	// Track if os/exec is imported
	hasExecImport := false
	execAlias := "exec"
	for _, imp := range file.Imports {
		importPath := strings.Trim(imp.Path.Value, `"`)
		if importPath == "os/exec" {
			hasExecImport = true
			if imp.Name != nil {
				execAlias = imp.Name.Name
			}
			break
		}
	}

	if !hasExecImport {
		return findings
	}

	// First pass: collect all variable declarations and assignments
	varValues := a.collectVariableValues(file)

	// Second pass: find exec.Command calls
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		// Check for exec.Command or exec.CommandContext
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}

		if ident.Name == execAlias && (sel.Sel.Name == "Command" || sel.Sel.Name == "CommandContext") {
			finding := a.analyzeExecCallWithVars(call, filePath, varValues)
			if finding != nil {
				findings = append(findings, *finding)
			}
		}

		return true
	})

	return findings
}

// collectVariableValues collects string variable declarations and assignments from the AST.
func (a *GoAnalyzer) collectVariableValues(file *ast.File) map[string]string {
	varValues := make(map[string]string)

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		// Handle var declarations: var cmd = "bash"
		case *ast.GenDecl:
			if node.Tok == token.VAR || node.Tok == token.CONST {
				for _, spec := range node.Specs {
					if valueSpec, ok := spec.(*ast.ValueSpec); ok {
						for i, name := range valueSpec.Names {
							if i < len(valueSpec.Values) {
								if val := extractStringValue(valueSpec.Values[i]); val != "" {
									varValues[name.Name] = val
								}
							}
						}
					}
				}
			}
		// Handle short declarations: cmd := "bash" or cmd := fmt.Sprintf(...)
		case *ast.AssignStmt:
			if node.Tok == token.DEFINE || node.Tok == token.ASSIGN {
				for i, lhs := range node.Lhs {
					if ident, ok := lhs.(*ast.Ident); ok {
						if i < len(node.Rhs) {
							if val := extractStringValue(node.Rhs[i]); val != "" {
								varValues[ident.Name] = val
							}
						}
					}
				}
			}
		}
		return true
	})

	return varValues
}

// extractStringValue extracts a string value from an expression.
// Handles string literals and fmt.Sprintf calls.
func extractStringValue(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind == token.STRING {
			return strings.Trim(e.Value, `"`)
		}
	case *ast.CallExpr:
		// Handle fmt.Sprintf("format", args...)
		if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok {
				if ident.Name == "fmt" && sel.Sel.Name == "Sprintf" {
					// Extract the format string
					if len(e.Args) > 0 {
						if lit, ok := e.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
							return strings.Trim(lit.Value, `"`)
						}
					}
				}
			}
		}
	}
	return ""
}

// analyzeExecCallWithVars analyzes an exec.Command call with variable resolution.
func (a *GoAnalyzer) analyzeExecCallWithVars(call *ast.CallExpr, filePath string, varValues map[string]string) *rules.Finding {
	pos := a.fset.Position(call.Pos())

	// Try to extract the command being executed
	var cmdName string
	var cmdArgs []string
	var isVariable bool
	var varName string

	// Determine argument offset (CommandContext has context as first arg)
	argOffset := 0
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		if sel.Sel.Name == "CommandContext" {
			argOffset = 1
		}
	}

	if len(call.Args) > argOffset {
		arg := call.Args[argOffset]

		// Check if it's a string literal
		if lit, ok := arg.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			cmdName = strings.Trim(lit.Value, `"`)
		} else if ident, ok := arg.(*ast.Ident); ok {
			// It's a variable - try to resolve it
			isVariable = true
			varName = ident.Name
			if val, found := varValues[ident.Name]; found {
				cmdName = val
			}
		} else if sel, ok := arg.(*ast.SelectorExpr); ok {
			// It's a selector like pkg.Var or struct.Field
			isVariable = true
			varName = formatSelector(sel)
		}
	}

	// Extract additional arguments (also try to resolve variables)
	for i := argOffset + 1; i < len(call.Args); i++ {
		arg := call.Args[i]
		if lit, ok := arg.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			cmdArgs = append(cmdArgs, strings.Trim(lit.Value, `"`))
		} else if ident, ok := arg.(*ast.Ident); ok {
			if val, found := varValues[ident.Name]; found {
				cmdArgs = append(cmdArgs, val)
			} else {
				cmdArgs = append(cmdArgs, "<"+ident.Name+">")
			}
		}
	}

	// Handle case where command couldn't be resolved
	if cmdName == "" {
		severity := rules.SeverityWarning
		message := "exec.Command with dynamic/unresolved command"
		details := map[string]interface{}{
			"command":     "<dynamic>",
			"is_variable": true,
		}

		if varName != "" {
			message = fmt.Sprintf("exec.Command using variable '%s' - value could not be resolved at compile time", varName)
			details["variable"] = varName
		}

		return &rules.Finding{
			RuleID:   "CCG005",
			Category: rules.CategoryExecCommand,
			Severity: severity,
			Message:  message,
			Location: rules.Location{
				File:   filePath,
				Line:   pos.Line,
				Column: pos.Column,
			},
			Details:    details,
			Suggestion: "Consider using a constant or ensure the variable value is available in your container",
		}
	}

	// Normalize the binary name (strip path prefix)
	binaryName := cmdName
	if idx := strings.LastIndex(cmdName, "/"); idx != -1 {
		binaryName = cmdName[idx+1:]
	}

	// Check if it's a shell command
	isShell := isShellCommand(binaryName)

	// If it's a shell with -c flag, parse the shell command to extract binaries
	var shellBinaries []string
	var shellCmdStr string
	if isShell && len(cmdArgs) >= 2 && cmdArgs[0] == "-c" {
		shellCmdStr = strings.Join(cmdArgs[1:], " ")

		// If the shell command is an unresolved variable like <varName>, try to resolve it
		if strings.HasPrefix(shellCmdStr, "<") && strings.HasSuffix(shellCmdStr, ">") {
			varNameInShell := strings.Trim(shellCmdStr, "<>")
			if resolvedVal, found := varValues[varNameInShell]; found {
				shellCmdStr = resolvedVal
			}
		}

		// Only parse if it's not an unresolved variable
		if !strings.HasPrefix(shellCmdStr, "<") {
			shellBinaries = extractBinariesFromShellCommand(shellCmdStr)

			// Track each binary found in the shell command
			for _, bin := range shellBinaries {
				binUsage := BinaryUsage{
					Binary:   bin,
					Args:     []string{},
					File:     filePath,
					Line:     pos.Line,
					Column:   pos.Column,
					IsShell:  false,
					ShellCmd: shellCmdStr,
				}
				a.detectedBinaries[bin] = append(a.detectedBinaries[bin], binUsage)
			}
		}
	}

	// Track this binary usage (the shell itself)
	usage := BinaryUsage{
		Binary:        binaryName,
		Args:          cmdArgs,
		File:          filePath,
		Line:          pos.Line,
		Column:        pos.Column,
		IsShell:       isShell,
		ShellCmd:      shellCmdStr,
		ShellBinaries: shellBinaries,
	}
	a.detectedBinaries[binaryName] = append(a.detectedBinaries[binaryName], usage)

	// Create finding
	severity := rules.SeverityWarning
	ruleID := "CCG001"
	message := fmt.Sprintf("External binary '%s' executed - verify it's available in your container", binaryName)
	suggestion := fmt.Sprintf("Ensure '%s' is installed in your container image or use a pure Go alternative", binaryName)

	if isShell {
		ruleID = "CCG002"
		message = fmt.Sprintf("Shell '%s' executed - verify shell is available in your container", binaryName)
		suggestion = "Ensure your base image has a shell, or use pure Go alternatives for scratch/distroless images"

		if len(shellBinaries) > 0 {
			message += fmt.Sprintf(" (shell command uses: %s)", strings.Join(shellBinaries, ", "))
		}
	}

	details := map[string]interface{}{
		"command": cmdName,
		"args":    cmdArgs,
	}

	if isVariable {
		details["resolved_from"] = varName
		message += fmt.Sprintf(" (resolved from variable '%s')", varName)
	}

	if len(shellBinaries) > 0 {
		details["shell_binaries"] = shellBinaries
	}

	return &rules.Finding{
		RuleID:   ruleID,
		Category: rules.CategoryExecCommand,
		Severity: severity,
		Message:  message,
		Location: rules.Location{
			File:   filePath,
			Line:   pos.Line,
			Column: pos.Column,
		},
		Details:    details,
		Suggestion: suggestion,
	}
}

// formatSelector formats a selector expression as a string.
func formatSelector(sel *ast.SelectorExpr) string {
	if ident, ok := sel.X.(*ast.Ident); ok {
		return ident.Name + "." + sel.Sel.Name
	}
	return sel.Sel.Name
}

// isShellCommand checks if a binary name is a shell.
func isShellCommand(binary string) bool {
	shells := map[string]bool{
		"sh": true, "bash": true, "zsh": true, "csh": true, "tcsh": true,
		"ksh": true, "fish": true, "dash": true, "ash": true,
	}
	return shells[binary]
}

// extractBinariesFromShellCommand parses a shell command string and extracts binary names.
// It handles pipes, command chaining, sudo, nsenter, and other common patterns.
func extractBinariesFromShellCommand(shellCmd string) []string {
	var binaries []string
	seen := make(map[string]bool)

	// Shell built-ins and keywords to skip
	builtins := map[string]bool{
		"echo": true, "cd": true, "export": true, "set": true, "unset": true,
		"if": true, "then": true, "else": true, "fi": true, "for": true, "do": true, "done": true,
		"while": true, "until": true, "case": true, "esac": true, "function": true,
		"return": true, "exit": true, "break": true, "continue": true,
		"true": true, "false": true, "test": true, "[": true, "[[": true,
		"read": true, "printf": true, "local": true, "declare": true,
		"source": true, ".": true, "eval": true, "exec": true,
	}

	// Commands that take another command as argument (prefix commands)
	prefixCommands := map[string]bool{
		"sudo": true, "nohup": true, "nice": true, "time": true, "timeout": true,
		"strace": true, "ltrace": true, "env": true, "xargs": true,
		"nsenter": true, "unshare": true, "chroot": true,
		"su": true, "runuser": true, "setpriv": true,
	}

	// Split by common command separators: |, &&, ||, ;, newline
	// Also handle $() and `` for command substitution
	separators := regexp.MustCompile(`[|;&\n]|&&|\|\|`)
	parts := separators.Split(shellCmd, -1)

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Extract binaries from this command part
		extractedBins := extractBinariesFromCommandPart(part, builtins, prefixCommands)
		for _, bin := range extractedBins {
			if !seen[bin] {
				seen[bin] = true
				binaries = append(binaries, bin)
			}
		}
	}

	return binaries
}

// extractBinariesFromCommandPart extracts binaries from a single command part.
func extractBinariesFromCommandPart(part string, builtins, prefixCommands map[string]bool) []string {
	var binaries []string

	// Tokenize the command part
	tokens := tokenizeShellCommand(part)
	if len(tokens) == 0 {
		return binaries
	}

	// Process tokens - only the first token (or first after prefix commands) is a binary
	i := 0
	for i < len(tokens) {
		token := tokens[i]

		// Skip empty tokens
		if token == "" {
			i++
			continue
		}

		// Skip flags
		if strings.HasPrefix(token, "-") {
			i++
			continue
		}

		// Skip variable assignments (VAR=value)
		if strings.Contains(token, "=") && !strings.HasPrefix(token, "-") {
			i++
			continue
		}

		// Skip shell variables and substitutions
		if strings.HasPrefix(token, "$") || strings.HasPrefix(token, "`") ||
			strings.HasPrefix(token, "(") || strings.HasPrefix(token, "{") {
			i++
			continue
		}

		// Extract binary name (strip path)
		binary := token
		if idx := strings.LastIndex(token, "/"); idx != -1 {
			binary = token[idx+1:]
		}

		// Skip if it's a builtin
		if builtins[binary] {
			// Skip to next command separator or end
			i++
			for i < len(tokens) {
				i++
			}
			continue
		}

		// Skip if it looks like an argument (not a command)
		// - Contains special characters that indicate it's data
		// - Is a common argument pattern
		if looksLikeArgument(token) {
			i++
			continue
		}

		// Add the binary
		binaries = append(binaries, binary)

		// If it's a prefix command (sudo, nsenter, etc.), continue to find the actual command
		if prefixCommands[binary] {
			i++
			// Skip flags for prefix commands
			for i < len(tokens) && strings.HasPrefix(tokens[i], "-") {
				// Handle flags with values like --net=/path
				if strings.Contains(tokens[i], "=") {
					i++
					continue
				}
				i++
				// Skip the flag's value if it's a separate token
				if i < len(tokens) && !strings.HasPrefix(tokens[i], "-") {
					// Check if this looks like a flag value (path, number, etc.)
					nextToken := tokens[i]
					if looksLikeArgument(nextToken) {
						i++
					}
				}
			}
			continue
		}

		// We found a command, skip all its arguments until end
		i++
		for i < len(tokens) {
			i++
		}
	}

	return binaries
}

// looksLikeArgument returns true if the token looks like a command argument rather than a binary.
func looksLikeArgument(token string) bool {
	// Paths (contain / but are clearly file paths)
	if strings.HasPrefix(token, "/") && (strings.Contains(token, ".") ||
		strings.HasPrefix(token, "/etc/") || strings.HasPrefix(token, "/var/") ||
		strings.HasPrefix(token, "/tmp/") || strings.HasPrefix(token, "/proc/") ||
		strings.HasPrefix(token, "/sys/") || strings.HasPrefix(token, "/dev/") ||
		strings.HasPrefix(token, "/home/") || strings.HasPrefix(token, "/usr/")) {
		return true
	}

	// URLs
	if strings.HasPrefix(token, "http://") || strings.HasPrefix(token, "https://") ||
		strings.HasPrefix(token, "ftp://") {
		return true
	}

	// File extensions
	if strings.HasSuffix(token, ".txt") || strings.HasSuffix(token, ".log") ||
		strings.HasSuffix(token, ".json") || strings.HasSuffix(token, ".yaml") ||
		strings.HasSuffix(token, ".yml") || strings.HasSuffix(token, ".xml") ||
		strings.HasSuffix(token, ".tar") || strings.HasSuffix(token, ".gz") ||
		strings.HasSuffix(token, ".zip") || strings.HasSuffix(token, ".sh") ||
		strings.HasSuffix(token, ".conf") || strings.HasSuffix(token, ".cfg") {
		return true
	}

	// Contains special characters that indicate it's data/pattern
	if strings.ContainsAny(token, "@:{}[]'\"\\") {
		return true
	}

	// Numeric values
	if _, err := fmt.Sscanf(token, "%d", new(int)); err == nil {
		return true
	}

	// IP addresses
	if regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+`).MatchString(token) {
		return true
	}

	return false
}

// tokenizeShellCommand splits a shell command into tokens, handling quotes.
func tokenizeShellCommand(cmd string) []string {
	var tokens []string
	var current strings.Builder
	inSingleQuote := false
	inDoubleQuote := false

	for i := 0; i < len(cmd); i++ {
		c := cmd[i]

		switch {
		case c == '\'' && !inDoubleQuote:
			inSingleQuote = !inSingleQuote
		case c == '"' && !inSingleQuote:
			inDoubleQuote = !inDoubleQuote
		case c == ' ' && !inSingleQuote && !inDoubleQuote:
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
		default:
			current.WriteByte(c)
		}
	}

	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}

	return tokens
}

// AnalyzeBuildTags checks for CGO-related build tags.
func (a *GoAnalyzer) AnalyzeBuildTags(filePath string) ([]rules.Finding, error) {
	var findings []rules.Finding

	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	content := string(src)
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		// Check for CGO build tags
		if strings.Contains(line, "// +build cgo") || strings.Contains(line, "//go:build cgo") {
			findings = append(findings, rules.Finding{
				RuleID:   "CCG010",
				Category: rules.CategoryCGO,
				Severity: rules.SeverityError,
				Message:  "CGO build tag detected - this file requires CGO to be enabled",
				Location: rules.Location{
					File: filePath,
					Line: i + 1,
				},
				Suggestion: "Consider providing a pure Go alternative or ensure CGO is properly configured for your target platform",
			})
		}
	}

	return findings, nil
}

// PackageInfo holds information about a Go package from go list.
type PackageInfo struct {
	ImportPath string   `json:"ImportPath"`
	Name       string   `json:"Name"`
	CgoFiles   []string `json:"CgoFiles"`
	CFiles     []string `json:"CFiles"`
	Deps       []string `json:"Deps"`
	Standard   bool     `json:"Standard"`
}

// AnalyzeDependencies dynamically analyzes all dependencies of a Go project
// to detect CGO usage, C files, and other compatibility issues.
func (a *GoAnalyzer) AnalyzeDependencies(projectPath string) ([]rules.Finding, error) {
	var findings []rules.Finding

	// Run go list to get all dependencies with their details
	cmd := exec.Command("go", "list", "-json", "./...")
	cmd.Dir = projectPath
	output, err := cmd.Output()
	if err != nil {
		// Try without ./... for single package
		cmd = exec.Command("go", "list", "-json", ".")
		cmd.Dir = projectPath
		output, err = cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("failed to run go list: %w", err)
		}
	}

	// Parse JSON output (go list outputs multiple JSON objects, not an array)
	decoder := json.NewDecoder(strings.NewReader(string(output)))
	var packages []PackageInfo
	for decoder.More() {
		var pkg PackageInfo
		if err := decoder.Decode(&pkg); err != nil {
			continue
		}
		packages = append(packages, pkg)
	}

	// Analyze each package
	for _, pkg := range packages {
		// Check for CGO files in the package
		if len(pkg.CgoFiles) > 0 {
			for _, cgoFile := range pkg.CgoFiles {
				findings = append(findings, rules.Finding{
					RuleID:   "CCG012",
					Category: rules.CategoryCGO,
					Severity: rules.SeverityWarning,
					Message:  fmt.Sprintf("Package '%s' contains CGO file: %s", pkg.ImportPath, cgoFile),
					Location: rules.Location{
						File: filepath.Join(projectPath, cgoFile),
					},
					Details: map[string]interface{}{
						"package":  pkg.ImportPath,
						"cgo_file": cgoFile,
					},
					Suggestion: "This package uses CGO - ensure CGO_ENABLED=1 and required C libraries are available, or find a pure Go alternative",
				})
			}
		}

		// Check for C files
		if len(pkg.CFiles) > 0 {
			for _, cFile := range pkg.CFiles {
				findings = append(findings, rules.Finding{
					RuleID:   "CCG013",
					Category: rules.CategoryCGO,
					Severity: rules.SeverityWarning,
					Message:  fmt.Sprintf("Package '%s' contains C source file: %s", pkg.ImportPath, cFile),
					Location: rules.Location{
						File: filepath.Join(projectPath, cFile),
					},
					Details: map[string]interface{}{
						"package": pkg.ImportPath,
						"c_file":  cFile,
					},
					Suggestion: "C source files require CGO and a C compiler - ensure build environment has gcc/clang",
				})
			}
		}
	}

	// Now check all transitive dependencies for CGO
	depFindings, err := a.analyzeTransitiveDeps(projectPath)
	if err == nil {
		findings = append(findings, depFindings...)
	}

	return findings, nil
}

// analyzeTransitiveDeps checks all transitive dependencies for CGO usage.
func (a *GoAnalyzer) analyzeTransitiveDeps(projectPath string) ([]rules.Finding, error) {
	var findings []rules.Finding

	// Get all dependencies including transitive ones
	cmd := exec.Command("go", "list", "-json", "-deps", "./...")
	cmd.Dir = projectPath
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	// Track which packages use CGO
	cgoPackages := make(map[string]bool)
	allPackages := make(map[string]PackageInfo)

	decoder := json.NewDecoder(strings.NewReader(string(output)))
	for decoder.More() {
		var pkg PackageInfo
		if err := decoder.Decode(&pkg); err != nil {
			continue
		}
		allPackages[pkg.ImportPath] = pkg

		// Check if this dependency uses CGO
		if len(pkg.CgoFiles) > 0 || len(pkg.CFiles) > 0 {
			cgoPackages[pkg.ImportPath] = true
		}
	}

	// Report CGO dependencies (excluding standard library which is expected)
	for pkgPath, pkg := range allPackages {
		if cgoPackages[pkgPath] && !pkg.Standard {
			severity := rules.SeverityWarning
			// Third-party CGO packages are more concerning
			if !strings.HasPrefix(pkgPath, "golang.org/") && !strings.HasPrefix(pkgPath, "google.golang.org/") {
				severity = rules.SeverityWarning
			}

			cgoFilesList := append(pkg.CgoFiles, pkg.CFiles...)
			findings = append(findings, rules.Finding{
				RuleID:   "CCG014",
				Category: rules.CategoryCGO,
				Severity: severity,
				Message:  fmt.Sprintf("Dependency '%s' uses CGO (%d CGO/C files)", pkgPath, len(cgoFilesList)),
				Location: rules.Location{
					File: projectPath,
				},
				Details: map[string]interface{}{
					"package":   pkgPath,
					"cgo_files": pkg.CgoFiles,
					"c_files":   pkg.CFiles,
				},
				Suggestion: "This dependency requires CGO - ensure glibc/musl is available in container or find a pure Go alternative",
			})
		}
	}

	return findings, nil
}

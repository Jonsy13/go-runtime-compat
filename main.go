// Package main provides the entry point for the go-runtime-compat CLI tool.
// go-runtime-compat is a static analyzer that detects container compatibility issues in Go projects.
package main

import (
	"os"

	"github.com/Jonsy13/go-runtime-compat/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}

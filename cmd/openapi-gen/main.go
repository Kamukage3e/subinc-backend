package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/subinc/subinc-backend/internal/openapigen"
)

func main() {
	dir := flag.String("dir", "./internal/admin/billing-management", "Target directory to scan")
	out := flag.String("out", "", "Output OpenAPI YAML file (optional)")
	verbose := flag.Bool("verbose", false, "Verbose logging")
	title := flag.String("title", "", "API title (defaults to directory name)")
	version := flag.String("version", "1.0.0", "API version")
	flag.Parse()

	if *dir == "" {
		fmt.Fprintln(os.Stderr, "--dir is required")
		os.Exit(1)
	}

	if *out == "" {
		// Use <folder-name>_openapi.yaml as default
		folder := filepath.Base(filepath.Clean(*dir))
		*out = folder + "_openapi.yaml"
	}

	// Always overwrite output file if exists
	if _, err := os.Stat(*out); err == nil {
		if err := os.Remove(*out); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to remove existing output file: %v\n", err)
			os.Exit(1)
		}
	}

	// If title not provided, use the directory name
	apiTitle := *title
	if apiTitle == "" {
		// Get the last part of the directory path as the default title
		dirParts := strings.Split(*dir, string(filepath.Separator))
		for i := len(dirParts) - 1; i >= 0; i-- {
			if dirParts[i] != "" {
				apiTitle = strings.ReplaceAll(dirParts[i], "-", " ")
				apiTitle = strings.ReplaceAll(apiTitle, "_", " ")
				apiTitle = strings.Title(apiTitle) + " API"
				break
			}
		}
	}

	err := openapigen.GenerateOpenAPI(openapigen.Options{
		Dir:     *dir,
		Out:     *out,
		Verbose: *verbose,
		Title:   apiTitle,
		Version: *version,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if *verbose {
		fmt.Printf("OpenAPI spec written to %s\n", *out)
	}
}

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/subinc/subinc-backend/internal/swaggerannotate"
)

func main() {
	dir := flag.String("dir", "./internal/admin/billing-management", "Target directory to annotate")
	dryRun := flag.Bool("dry-run", false, "Show changes but do not write")
	write := flag.Bool("write", false, "Write changes to files")
	flag.Parse()

	if !*dryRun && !*write {
		fmt.Fprintln(os.Stderr, "Specify --dry-run or --write")
		os.Exit(2)
	}

	err := swaggerannotate.Annotate(swaggerannotate.AnnotateOptions{
		Dir:    *dir,
		DryRun: *dryRun,
		Write:  *write,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "swagger-annotate error: %v\n", err)
		os.Exit(1)
	}
}

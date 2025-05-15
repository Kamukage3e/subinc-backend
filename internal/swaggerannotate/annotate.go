package swaggerannotate

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"strings"
)

type AnnotateOptions struct {
	Dir    string
	DryRun bool
	Write  bool
}

func Annotate(opts AnnotateOptions) error {
	files, _, fileMap, err := ParseDir(opts.Dir)
	if err != nil {
		return fmt.Errorf("parse dir: %w", err)
	}
	handlers := FindHandlerFuncs(files)
	for _, h := range handlers {
		annotation := GenerateSwaggerAnnotation(h)
		filePath := fileMap[h.File]
		content, err := ioutil.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("read file: %w", err)
		}
		lines := strings.Split(string(content), "\n")
		insertLine := int(h.Func.Pos()) - 1
		if insertLine < 0 || insertLine > len(lines) {
			insertLine = len(lines)
		}
		// Find existing annotation block
		start, end := -1, -1
		for i := insertLine - 1; i >= 0 && i < len(lines); i-- {
			if strings.HasPrefix(strings.TrimSpace(lines[i]), "// swagger:route") {
				start = i
				// Find end of annotation block
				for j := i + 1; j < insertLine && j < len(lines); j++ {
					if !strings.HasPrefix(strings.TrimSpace(lines[j]), "//") && strings.TrimSpace(lines[j]) != "" {
						end = j
						break
					}
				}
				if end == -1 {
					end = insertLine
				}
				break
			}
		}
		if start >= len(lines) || start < -1 {
			start = -1
		}
		if end > len(lines) || end < -1 {
			end = len(lines)
		}
		var out bytes.Buffer
		w := bufio.NewWriter(&out)
		if start != -1 && end != -1 && start < end && start < len(lines) && end <= len(lines) {
			// Existing annotation: check if matches, update if not
			existing := strings.Join(lines[start:end], "\n")
			if strings.TrimSpace(existing) != strings.TrimSpace(annotation) {
				for i := 0; i < start; i++ {
					w.WriteString(lines[i])
					w.WriteString("\n")
				}
				w.WriteString(annotation)
				w.WriteString("\n")
				for i := end; i < len(lines); i++ {
					w.WriteString(lines[i])
					w.WriteString("\n")
				}
			} else {
				continue // No change needed
			}
		} else {
			// No annotation: insert above handler
			for i := 0; i < insertLine && i < len(lines); i++ {
				w.WriteString(lines[i])
				w.WriteString("\n")
			}
			w.WriteString(annotation)
			w.WriteString("\n")
			for i := insertLine; i < len(lines); i++ {
				w.WriteString(lines[i])
				w.WriteString("\n")
			}
		}
		w.Flush()
		if opts.DryRun {
			fmt.Printf("--- %s ---\n%s\n", filePath, out.String())
		} else if opts.Write {
			if err := ioutil.WriteFile(filePath, out.Bytes(), 0644); err != nil {
				return fmt.Errorf("write file: %w", err)
			}
		}
	}
	return nil
}

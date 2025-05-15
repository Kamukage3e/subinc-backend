package openapigen

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type HandlerFunc struct {
	File         *ast.File
	Func         *ast.FuncDecl
	FilePath     string
	Comment      string
	Params       map[string]string
	Returns      map[string]string
	Tags         []string
	Package      string
	Body         *ast.BlockStmt // Store the function body for analysis
	IsPublic     bool           // Whether the function is exported/public
	Deprecated   bool           // Whether the handler is deprecated
	QueryParams  []string       // Store detected query parameters
	PathParams   []string       // Store detected path parameters
	ErrorCodes   []string       // Store detected error status codes
	RelatedTypes []string       // Store types related to this handler
}

func ParseDir(dir string) ([]*ast.File, *token.FileSet, map[*ast.File]string, error) {
	fset := token.NewFileSet()
	files := []*ast.File{}
	fileMap := make(map[*ast.File]string)
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || filepath.Ext(path) != ".go" {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return err
		}
		files = append(files, f)
		fileMap[f] = path
		return nil
	})
	if err != nil {
		return nil, nil, nil, err
	}
	return files, fset, fileMap, nil
}

// extractCommentText extracts structured documentation from comment text
// Parses comment lines with certain prefixes:
// @Summary - Short description of operation
// @Description - Detailed description
// @Tags - Comma-separated tags
// @Param - Parameter description
// @Accept - Accepted MIME types
// @Produce - Produced MIME types
// @Success - Success response
// @Failure - Error response
// @Router - API route and method
func extractCommentText(commentGroup *ast.CommentGroup) (string, map[string]string) {
	if commentGroup == nil {
		return "", nil
	}

	fullComment := commentGroup.Text()
	annotations := make(map[string]string)

	// Extract the first line for summary if no @Summary is provided
	firstLineForSummary := ""

	lines := strings.Split(fullComment, "\n")
	if len(lines) > 0 {
		firstLineForSummary = strings.TrimSpace(lines[0])
	}

	// Process annotations and collect description lines
	var descriptionLines []string
	inDescription := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "@") {
			inDescription = false
			parts := strings.SplitN(line, " ", 2)
			if len(parts) == 2 {
				key := strings.TrimPrefix(parts[0], "@")
				annotations[key] = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(line, "//") {
			// Clean the comment marker
			cleaned := strings.TrimSpace(strings.TrimPrefix(line, "//"))
			if cleaned != "" {
				descriptionLines = append(descriptionLines, cleaned)
			}
		} else if !strings.HasPrefix(line, "@") {
			if inDescription || len(annotations) == 0 {
				descriptionLines = append(descriptionLines, line)
			}
		}
	}

	// If we have description lines and no explicit @Description, use them
	if len(descriptionLines) > 0 && annotations["Description"] == "" {
		annotations["Description"] = strings.Join(descriptionLines, "\n")
	}

	// If we have a first line and no explicit @Summary, use it
	if firstLineForSummary != "" && annotations["Summary"] == "" {
		// Remove comment markers and trim
		summary := strings.TrimSpace(strings.TrimPrefix(firstLineForSummary, "//"))
		// Limit to a reasonable length
		if len(summary) > 0 {
			if len(summary) > 120 {
				summary = summary[:120] + "..."
			}
			annotations["Summary"] = summary
		}
	}

	// Extract parameter information from comments
	paramPattern := regexp.MustCompile(`(?i)(\w+)\s+param(?:eter)?(?:s)?:?\s*(.+)`)
	for _, line := range lines {
		if matches := paramPattern.FindStringSubmatch(line); len(matches) > 2 {
			paramName := strings.ToLower(matches[1])
			paramDesc := strings.TrimSpace(matches[2])
			annotations["Param_"+paramName] = paramDesc
		}
	}

	// Extract return information from comments
	returnPattern := regexp.MustCompile(`(?i)returns?:?\s*(.+)`)
	for _, line := range lines {
		if matches := returnPattern.FindStringSubmatch(line); len(matches) > 1 {
			annotations["Return"] = strings.TrimSpace(matches[1])
		}
	}

	// If the only comments are godoc-style function comments, try to extract method and path
	if annotations["Router"] == "" {
		// Try to extract API path and method from comments
		for _, line := range lines {
			httpMethods := []string{"GET", "POST", "PUT", "DELETE", "PATCH"}
			for _, method := range httpMethods {
				if strings.Contains(strings.ToUpper(line), method+" ") && strings.Contains(line, "/") {
					// This looks like "GET /some/path" pattern
					routeInfo := method + " "
					// Extract the path after the method
					parts := strings.SplitN(line, method+" ", 2)
					if len(parts) > 1 {
						pathPart := parts[1]
						// Find the path segment
						pathStart := 0
						if strings.Contains(pathPart, "/") {
							pathStart = strings.Index(pathPart, "/")
							pathEnd := len(pathPart)
							for i := pathStart; i < len(pathPart); i++ {
								if pathPart[i] == ' ' || pathPart[i] == '\t' || pathPart[i] == '\n' {
									pathEnd = i
									break
								}
							}
							path := pathPart[pathStart:pathEnd]
							routeInfo += path
							annotations["Router"] = routeInfo
							break
						}
					}
				}
			}
		}
	}

	// Extract any deprecation notice from the comments
	if strings.Contains(fullComment, "@deprecated") ||
		strings.Contains(strings.ToLower(fullComment), "deprecated") {
		annotations["Deprecated"] = "true"

		// Try to extract the deprecation message
		deprecationLines := []string{}
		inDeprecation := false

		for _, line := range lines {
			line = strings.TrimSpace(line)

			// Start capturing after finding the deprecated keyword
			if strings.Contains(strings.ToLower(line), "deprecated") {
				inDeprecation = true
				// Extract text after "deprecated"
				parts := strings.SplitN(strings.ToLower(line), "deprecated", 2)
				if len(parts) > 1 {
					message := strings.TrimSpace(parts[1])
					if message != "" {
						deprecationLines = append(deprecationLines, message)
					}
				}
				continue
			}

			// Continue capturing lines until we hit another annotation
			if inDeprecation && !strings.HasPrefix(line, "@") {
				deprecationLines = append(deprecationLines, line)
			} else if strings.HasPrefix(line, "@") {
				inDeprecation = false
			}
		}

		if len(deprecationLines) > 0 {
			annotations["DeprecationMessage"] = strings.Join(deprecationLines, " ")
		}
	}

	return fullComment, annotations
}

// FormatType converts an AST expression to a string representation
// This is a helper function to avoid name collision with exprToString in generate.go
func FormatType(expr interface{}) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return FormatType(t.X) + "." + t.Sel.Name
	case *ast.StarExpr:
		return "*" + FormatType(t.X)
	case *ast.ArrayType:
		return "[]" + FormatType(t.Elt)
	case *ast.MapType:
		return "map[" + FormatType(t.Key) + "]" + FormatType(t.Value)
	case *ast.InterfaceType:
		return "interface{}"
	case *ast.StructType:
		return "struct{...}"
	case *ast.FuncType:
		return "func(...) ..."
	case *ast.CompositeLit:
		return FormatType(t.Type)
	case *ast.CallExpr:
		return FormatType(t.Fun) + "(...)"
	case *ast.BasicLit:
		return t.Value
	default:
		return fmt.Sprintf("%T", expr)
	}
}

func FindHandlerFuncs(files []*ast.File) []HandlerFunc {
	handlers := []HandlerFunc{}
	for _, f := range files {
		pkg := f.Name.Name // package name

		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Type.Params == nil {
				continue
			}

			// Check if this is a method with a receiver (likely a handler method)
			var receiverType string
			if fn.Recv != nil && len(fn.Recv.List) > 0 {
				expr := fn.Recv.List[0].Type
				if starExpr, ok := expr.(*ast.StarExpr); ok {
					if ident, ok := starExpr.X.(*ast.Ident); ok {
						receiverType = ident.Name
					}
				} else if ident, ok := expr.(*ast.Ident); ok {
					receiverType = ident.Name
				}
			}

			// Check if this is a fiber handler (has *fiber.Ctx parameter)
			isHandler := false
			params := make(map[string]string)
			for _, param := range fn.Type.Params.List {
				paramType := ""

				switch t := param.Type.(type) {
				case *ast.StarExpr:
					if sel, ok := t.X.(*ast.SelectorExpr); ok {
						if sel.Sel.Name == "Ctx" {
							isHandler = true
						}
						paramType = FormatType(t)
					}
				case *ast.SelectorExpr:
					paramType = FormatType(t)
				case *ast.Ident:
					paramType = t.Name
				}

				if len(param.Names) > 0 {
					for _, name := range param.Names {
						params[name.Name] = paramType
					}
				}
			}

			// If not a direct Fiber handler, check if it could be a function that returns a handler
			if !isHandler && fn.Type.Results != nil {
				for _, result := range fn.Type.Results.List {
					resultType := FormatType(result.Type)
					if strings.Contains(resultType, "fiber.Handler") {
						isHandler = true
						break
					}
				}
			}

			if !isHandler {
				continue
			}

			// Extract return types
			returns := make(map[string]string)
			if fn.Type.Results != nil {
				for i, result := range fn.Type.Results.List {
					resultType := FormatType(result.Type)
					if len(result.Names) > 0 {
						for _, name := range result.Names {
							returns[name.Name] = resultType
						}
					} else {
						returns[fmt.Sprintf("result%d", i)] = resultType
					}
				}
			}

			// Extract any tags from comments
			comment, annotations := extractCommentText(fn.Doc)
			tags := []string{}
			if tagStr, ok := annotations["Tags"]; ok {
				for _, tag := range strings.Split(tagStr, ",") {
					tags = append(tags, strings.TrimSpace(tag))
				}
			}

			// If no tags specified but we have a receiver type, use that as a tag
			if len(tags) == 0 && receiverType != "" {
				// Convert HandlerName to "handler-name" format for tag
				tag := receiverType
				if strings.HasSuffix(tag, "Handler") {
					tag = strings.TrimSuffix(tag, "Handler")
				}
				// Convert PascalCase to kebab-case
				tag = camelToKebab(tag)
				tags = append(tags, tag)
			}

			// Extract query parameters and path parameters from function body
			var queryParams, pathParams, errorCodes []string
			var relatedTypes []string

			if fn.Body != nil {
				// Extract query parameters
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					if callExpr, ok := n.(*ast.CallExpr); ok {
						if selExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
							// Check for c.Query(), c.QueryParam(), c.Params() patterns
							if selExpr.Sel.Name == "Query" || selExpr.Sel.Name == "QueryParam" {
								if len(callExpr.Args) > 0 {
									if lit, ok := callExpr.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
										paramName := strings.Trim(lit.Value, "\"'")
										if !contains(queryParams, paramName) {
											queryParams = append(queryParams, paramName)
										}
									}
								}
							} else if selExpr.Sel.Name == "Params" {
								if len(callExpr.Args) > 0 {
									if lit, ok := callExpr.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
										paramName := strings.Trim(lit.Value, "\"'")
										if !contains(pathParams, paramName) {
											pathParams = append(pathParams, paramName)
										}
									}
								}
							} else if selExpr.Sel.Name == "Status" {
								// Find status codes used in responses
								if len(callExpr.Args) > 0 {
									if lit, ok := callExpr.Args[0].(*ast.BasicLit); ok && lit.Kind == token.INT {
										statusCode := lit.Value
										if !contains(errorCodes, statusCode) {
											errorCodes = append(errorCodes, statusCode)
										}
									} else if ident, ok := callExpr.Args[0].(*ast.Ident); ok {
										// It might be a constant like fiber.StatusBadRequest
										statusName := ident.Name
										// We'll use the statusNameToCode from generate.go
										if code := GetStatusCode(statusName); code != "" && !contains(errorCodes, code) {
											errorCodes = append(errorCodes, code)
										}
									} else if selExpr, ok := callExpr.Args[0].(*ast.SelectorExpr); ok {
										// It might be a constant like fiber.StatusBadRequest
										if pkg, ok := selExpr.X.(*ast.Ident); ok {
											statusFullName := pkg.Name + "." + selExpr.Sel.Name
											// We'll use the statusNameToCode from generate.go
											if code := GetStatusCode(statusFullName); code != "" && !contains(errorCodes, code) {
												errorCodes = append(errorCodes, code)
											}
										}
									}
								}
							}
						}
					}

					// Detect variable types to infer related schemas
					if assignStmt, ok := n.(*ast.AssignStmt); ok {
						for _, expr := range assignStmt.Rhs {
							if callExpr, ok := expr.(*ast.CallExpr); ok {
								// Look for patterns like model.New*() or similar
								if sel, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
									if x, ok := sel.X.(*ast.Ident); ok {
										if x.Name == "model" || strings.HasSuffix(x.Name, "Service") {
											typeName := sel.Sel.Name
											// If it's a New* constructor, extract the actual type
											if strings.HasPrefix(typeName, "New") {
												typeName = strings.TrimPrefix(typeName, "New")
											}
											if !contains(relatedTypes, typeName) {
												relatedTypes = append(relatedTypes, typeName)
											}
										}
									}
								}
							}

							// Look for struct type instantiation
							if compLit, ok := expr.(*ast.CompositeLit); ok {
								typeName := FormatType(compLit)
								if strings.Contains(typeName, ".") { // It has a package qualifier
									parts := strings.Split(typeName, ".")
									if len(parts) >= 2 {
										typeName = parts[1]
										if !contains(relatedTypes, typeName) {
											relatedTypes = append(relatedTypes, typeName)
										}
									}
								}
							}
						}
					}

					return true
				})
			}

			// Check if function is exported/public
			isPublic := ast.IsExported(fn.Name.Name)

			// Check if function is deprecated
			isDeprecated := annotations["Deprecated"] == "true"

			handlers = append(handlers, HandlerFunc{
				File:         f,
				Func:         fn,
				Comment:      comment,
				Params:       params,
				Returns:      returns,
				Tags:         tags,
				Package:      pkg,
				Body:         fn.Body,
				IsPublic:     isPublic,
				Deprecated:   isDeprecated,
				QueryParams:  queryParams,
				PathParams:   pathParams,
				ErrorCodes:   errorCodes,
				RelatedTypes: relatedTypes,
			})
		}
	}
	return handlers
}

// contains checks if a string is present in a slice
func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

// camelToKebab converts PascalCase or camelCase to kebab-case
func camelToKebab(s string) string {
	var result strings.Builder
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			result.WriteRune('-')
			result.WriteRune(r - 'A' + 'a')
		} else {
			result.WriteRune(r)
		}
	}
	return strings.ToLower(result.String())
}

// GetStatusCode is a wrapper for statusNameToCode to avoid duplication
func GetStatusCode(name string) string {
	statusMap := map[string]string{
		"StatusOK":                         "200",
		"StatusCreated":                    "201",
		"StatusAccepted":                   "202",
		"StatusNoContent":                  "204",
		"StatusBadRequest":                 "400",
		"StatusUnauthorized":               "401",
		"StatusForbidden":                  "403",
		"StatusNotFound":                   "404",
		"StatusMethodNotAllowed":           "405",
		"StatusNotAcceptable":              "406",
		"StatusRequestTimeout":             "408",
		"StatusConflict":                   "409",
		"StatusGone":                       "410",
		"StatusUnsupportedMediaType":       "415",
		"StatusUnprocessableEntity":        "422",
		"StatusInternalServerError":        "500",
		"StatusNotImplemented":             "501",
		"StatusBadGateway":                 "502",
		"StatusServiceUnavailable":         "503",
		"fiber.StatusOK":                   "200",
		"fiber.StatusCreated":              "201",
		"fiber.StatusAccepted":             "202",
		"fiber.StatusNoContent":            "204",
		"fiber.StatusBadRequest":           "400",
		"fiber.StatusUnauthorized":         "401",
		"fiber.StatusForbidden":            "403",
		"fiber.StatusNotFound":             "404",
		"fiber.StatusMethodNotAllowed":     "405",
		"fiber.StatusNotAcceptable":        "406",
		"fiber.StatusRequestTimeout":       "408",
		"fiber.StatusConflict":             "409",
		"fiber.StatusGone":                 "410",
		"fiber.StatusUnsupportedMediaType": "415",
		"fiber.StatusUnprocessableEntity":  "422",
		"fiber.StatusInternalServerError":  "500",
		"fiber.StatusNotImplemented":       "501",
		"fiber.StatusBadGateway":           "502",
		"fiber.StatusServiceUnavailable":   "503",
	}

	if code, ok := statusMap[name]; ok {
		return code
	}

	// Also handle simple integer literals
	intPattern := regexp.MustCompile(`^\d{3}$`)
	if intPattern.MatchString(name) {
		return name
	}

	return ""
}

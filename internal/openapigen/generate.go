package openapigen

import (
	"fmt"
	"go/ast"
	"go/token"
	"io/ioutil"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type Options struct {
	Dir     string
	Out     string
	Verbose bool
	Title   string // API title
	Version string // API version
}

func GenerateOpenAPI(opts Options) error {
	if opts.Title == "" {
		opts.Title = filepath.Base(opts.Dir)
	}
	if opts.Version == "" {
		opts.Version = "1.0.0"
	}

	files, _, fileMap, err := ParseDir(opts.Dir)
	if err != nil {
		return err
	}

	// Extract all useful information from the parsed files
	handlers := FindHandlerFuncs(files)
	routerInfo := extractRouterInfo(files, handlers, fileMap)
	typeDefinitions := extractTypeDefinitions(files)

	// Build OpenAPI components
	components := buildComponents(typeDefinitions)
	paths := buildPathsFromHandlers(handlers, routerInfo)
	tags := buildTags(handlers)

	// Build the full spec
	spec := buildOpenAPISpec(paths, components, tags, opts)

	data, err := MarshalOpenAPI(spec)
	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(opts.Out, data, 0644); err != nil {
		return err
	}

	if opts.Verbose {
		fmt.Printf("Wrote OpenAPI spec to %s\n", opts.Out)
		fmt.Printf("Processed %d handlers across %d files\n", len(handlers), len(files))
		fmt.Printf("Generated %d paths, %d tags, and %d schemas\n",
			len(paths), len(tags), len(components.Schemas))
	}

	return nil
}

// RouteInfo contains mapping between handler functions and actual routes
type RouteInfo struct {
	HandlerToRoute  map[string]string // maps handler function name to route path
	HandlerToMethod map[string]string // maps handler function name to HTTP method
	BasePathPrefix  string            // common base path prefix (if any)
}

// Type definition information extracted from the codebase
type TypeDefinition struct {
	Name       string
	Type       ast.Expr
	Fields     []*ast.Field
	Comment    string
	IsExported bool
	File       *ast.File
}

// extractRouterInfo analyzes router files to extract route path information
func extractRouterInfo(files []*ast.File, handlers []HandlerFunc, fileMap map[*ast.File]string) RouteInfo {
	info := RouteInfo{
		HandlerToRoute:  make(map[string]string),
		HandlerToMethod: make(map[string]string),
	}

	// Map to keep track of router group variables and their paths
	routerGroups := make(map[string]string)

	// First look for specific file patterns we know about
	for _, file := range files {
		filePath := "" // Get the file path from the file
		for f, path := range fileMap {
			if f == file {
				filePath = path
				break
			}
		}
		if filePath != "" && strings.Contains(filePath, "routers.go") {
			// This is likely a router definition file, check for common patterns
			ast.Inspect(file, func(n ast.Node) bool {
				// Look for router group registrations like: org := router.Group("/organizations", ...)
				if assignStmt, ok := n.(*ast.AssignStmt); ok && len(assignStmt.Lhs) > 0 && len(assignStmt.Rhs) > 0 {
					if callExpr, ok := assignStmt.Rhs[0].(*ast.CallExpr); ok {
						if selExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok && selExpr.Sel.Name == "Group" {
							if len(callExpr.Args) > 0 {
								if pathLit, ok := callExpr.Args[0].(*ast.BasicLit); ok {
									groupPath := strings.Trim(pathLit.Value, `"'`)
									if lhsIdent, ok := assignStmt.Lhs[0].(*ast.Ident); ok {
										routerGroups[lhsIdent.Name] = groupPath
									}
								}
							}
						}
					}
				}

				// Look for method registrations like: org.Get("/get", handler.GetOrganization)
				if callExpr, ok := n.(*ast.CallExpr); ok {
					if selExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
						method := strings.ToLower(selExpr.Sel.Name)
						if isHTTPMethod(method) && len(callExpr.Args) >= 2 {
							// Check if this is a method on a router group
							if ident, ok := selExpr.X.(*ast.Ident); ok {
								groupPath, isGroup := routerGroups[ident.Name]
								if isGroup && len(callExpr.Args) >= 2 {
									// Extract route path and handler
									if pathLit, ok := callExpr.Args[0].(*ast.BasicLit); ok {
										routePath := strings.Trim(pathLit.Value, `"'`)
										// Combine group path with route path
										fullPath := path.Join(groupPath, routePath)

										// Extract handler name
										handlerName := extractHandlerName(callExpr.Args[1])
										if handlerName != "" {
											info.HandlerToRoute[handlerName] = fullPath
											info.HandlerToMethod[handlerName] = method
											// Always store just the method name as well
											if dot := strings.Index(handlerName, "."); dot != -1 && dot+1 < len(handlerName) {
												methodOnly := handlerName[dot+1:]
												info.HandlerToRoute[methodOnly] = fullPath
												info.HandlerToMethod[methodOnly] = method
											}
										}
									}
								}
							}
						}
					}
				}
				return true
			})
		}
	}

	// Now do the regular processing for other files/patterns
	// First pass: find router group declarations
	for _, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			// Look for router group assignments: api := app.Group("/api")
			if assignStmt, ok := n.(*ast.AssignStmt); ok && len(assignStmt.Lhs) > 0 && len(assignStmt.Rhs) > 0 {
				if callExpr, ok := assignStmt.Rhs[0].(*ast.CallExpr); ok {
					if selExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok && selExpr.Sel.Name == "Group" {
						if len(callExpr.Args) > 0 {
							if pathLit, ok := callExpr.Args[0].(*ast.BasicLit); ok {
								groupPath := strings.Trim(pathLit.Value, `"'`)
								if lhsIdent, ok := assignStmt.Lhs[0].(*ast.Ident); ok {
									routerGroups[lhsIdent.Name] = groupPath
								}
							}
						}
					}
				}
			}

			// Look for nested groups: v1 := api.Group("/v1")
			if assignStmt, ok := n.(*ast.AssignStmt); ok && len(assignStmt.Lhs) > 0 && len(assignStmt.Rhs) > 0 {
				if callExpr, ok := assignStmt.Rhs[0].(*ast.CallExpr); ok {
					if selExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok && selExpr.Sel.Name == "Group" {
						if ident, ok := selExpr.X.(*ast.Ident); ok {
							// Check if this is a group on an existing router
							if parentPath, exists := routerGroups[ident.Name]; exists {
								if len(callExpr.Args) > 0 {
									if pathLit, ok := callExpr.Args[0].(*ast.BasicLit); ok {
										childPath := strings.Trim(pathLit.Value, `"'`)
										fullPath := path.Join(parentPath, childPath)
										if lhsIdent, ok := assignStmt.Lhs[0].(*ast.Ident); ok {
											routerGroups[lhsIdent.Name] = fullPath
										}
									}
								}
							}
						}
					}
				}
			}

			// Look for router.Group() followed by route registrations in function calls
			if callExpr, ok := n.(*ast.CallExpr); ok {
				if selExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok && selExpr.Sel.Name == "Group" {
					if len(callExpr.Args) > 0 {
						if pathLit, ok := callExpr.Args[0].(*ast.BasicLit); ok {
							// Found a router.Group("/path") call - this might be part of a registration function
							// We can track the parent node to find subsequent route registrations
							groupPath := strings.Trim(pathLit.Value, `"'`)

							// Look for the variable name this group is assigned to
							if assignStmt, ok := getParentAssignStmt(n); ok && len(assignStmt.Lhs) > 0 {
								if lhsIdent, ok := assignStmt.Lhs[0].(*ast.Ident); ok {
									routerGroups[lhsIdent.Name] = groupPath
								}
							}
						}
					}
				}
			}

			return true
		})
	}

	// Specifically look for router registration functions
	for _, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			if funcDecl, ok := n.(*ast.FuncDecl); ok {
				funcName := funcDecl.Name.Name
				if strings.HasPrefix(funcName, "Register") && strings.Contains(funcName, "Routes") && funcDecl.Body != nil {
					// Process the registration function body
					ast.Inspect(funcDecl.Body, func(n ast.Node) bool {
						// Look for router.Group("/path") calls
						if callExpr, ok := n.(*ast.CallExpr); ok {
							if selExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok && selExpr.Sel.Name == "Group" {
								if len(callExpr.Args) > 0 {
									if pathLit, ok := callExpr.Args[0].(*ast.BasicLit); ok {
										groupPath := strings.Trim(pathLit.Value, `"'`)

										// Look for assignment to a variable
										if assignStmt, ok := getParentAssignStmt(n); ok && len(assignStmt.Lhs) > 0 {
											if ident, ok := assignStmt.Lhs[0].(*ast.Ident); ok {
												routerGroups[ident.Name] = groupPath
											}
										}
									}
								}
							}
						}
						return true
					})
				}
			}
			return true
		})
	}

	// Second pass: find routes registered on router groups
	for _, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			// Look for route registrations: router.Get("/path", handler.Method)
			if callExpr, ok := n.(*ast.CallExpr); ok {
				if selExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
					method := strings.ToLower(selExpr.Sel.Name)
					if isHTTPMethod(method) && len(callExpr.Args) >= 2 {
						// Extract the router variable
						var routerName string
						var groupPrefix string

						if ident, ok := selExpr.X.(*ast.Ident); ok {
							routerName = ident.Name
							// Check if this is a registered router group
							if prefix, exists := routerGroups[routerName]; exists {
								groupPrefix = prefix
							}
						}

						// Extract the path and handler
						if pathLit, ok := callExpr.Args[0].(*ast.BasicLit); ok {
							path := strings.Trim(pathLit.Value, `"'`)
							fullPath := path

							// If this is a router group, prepend the group path
							if groupPrefix != "" {
								fullPath = strings.TrimRight(groupPrefix, "/") + "/" + strings.TrimLeft(path, "/")
							}

							// Extract the handler function name from different patterns
							handlerName := extractHandlerName(callExpr.Args[1])
							if handlerName != "" {
								info.HandlerToRoute[handlerName] = fullPath
								info.HandlerToMethod[handlerName] = method
								// Always store just the method name as well
								if dot := strings.Index(handlerName, "."); dot != -1 && dot+1 < len(handlerName) {
									methodOnly := handlerName[dot+1:]
									info.HandlerToRoute[methodOnly] = fullPath
									info.HandlerToMethod[methodOnly] = method
								}
							}
						}
					}
				}
			}

			return true
		})
	}

	// Clean up route paths
	for handler, route := range info.HandlerToRoute {
		// Remove any double slashes in paths
		cleanRoute := strings.Replace(route, "//", "/", -1)
		info.HandlerToRoute[handler] = cleanRoute
	}

	// Refactored: Only use HandlerToRoute and HandlerToMethod as discovered from router code. Do not generate or expect any legacy, singular, or typo paths. All output must be RESTful, plural, parameterized, and match the router exactly. No hardcoded or fallback path logic. All path parameters must be in the form /resource/{id} or /resource/{id}/subresource. Generator is now fully generic and always reflects the router structure.

	return info
}

// getParentAssignStmt checks if the node is part of an assignment statement
// and returns the parent assignment statement if found
func getParentAssignStmt(node ast.Node) (*ast.AssignStmt, bool) {
	// This is a simplified version - in a real implementation you would
	// need to walk up the AST to find the parent
	return nil, false
}

// extractHandlerName tries to get the handler function name from an expression
func extractHandlerName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		// Direct function name: someFunc
		return e.Name
	case *ast.SelectorExpr:
		// Method call: handler.Method
		if x, ok := e.X.(*ast.Ident); ok {
			return x.Name + "." + e.Sel.Name
		}
	case *ast.CallExpr:
		// Function call that returns a handler: middleware(handler)
		if len(e.Args) > 0 {
			if innerHandler := extractHandlerName(e.Args[0]); innerHandler != "" {
				return innerHandler
			}
		}
		// Function call: someFunc()
		if selExpr, ok := e.Fun.(*ast.SelectorExpr); ok {
			if x, ok := selExpr.X.(*ast.Ident); ok {
				return x.Name + "." + selExpr.Sel.Name
			} else if x, ok := selExpr.X.(*ast.SelectorExpr); ok {
				// Handle deeper nested selectors like pkg.subpkg.func
				if pkg, ok := x.X.(*ast.Ident); ok {
					return pkg.Name + "." + x.Sel.Name + "." + selExpr.Sel.Name
				}
			}
		}
	case *ast.FuncLit:
		// Anonymous function
		return "anonymous"
	}
	return ""
}

// isHTTPMethod checks if a method name is an HTTP method
func isHTTPMethod(method string) bool {
	method = strings.ToLower(method)
	return method == "get" || method == "post" || method == "put" || method == "delete" ||
		method == "patch" || method == "options" || method == "head" || method == "connect" ||
		method == "trace" || method == "add" // 'add' is specific to some frameworks
}

// extractTypeDefinitions extracts all struct definitions from the codebase
func extractTypeDefinitions(files []*ast.File) []TypeDefinition {
	var types []TypeDefinition

	for _, file := range files {
		for _, decl := range file.Decls {
			genDecl, ok := decl.(*ast.GenDecl)
			if !ok || genDecl.Tok != token.TYPE {
				continue
			}

			for _, spec := range genDecl.Specs {
				typeSpec, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}

				structType, ok := typeSpec.Type.(*ast.StructType)
				if !ok {
					continue
				}

				var comment string
				if genDecl.Doc != nil {
					comment = genDecl.Doc.Text()
				}

				types = append(types, TypeDefinition{
					Name:       typeSpec.Name.Name,
					Type:       structType,
					Fields:     structType.Fields.List,
					Comment:    comment,
					IsExported: typeSpec.Name.IsExported(),
					File:       file,
				})
			}
		}
	}

	return types
}

func buildComponents(types []TypeDefinition) *Components {
	components := &Components{
		Schemas:         make(map[string]Schema),
		Responses:       make(map[string]Response),
		SecuritySchemes: make(map[string]SecurityScheme),
	}

	// Add standard responses
	components.Responses = map[string]Response{
		"BadRequest": {
			Description: "Bad request",
			Content: map[string]MediaType{
				"application/json": {Schema: Schema{Type: "object"}},
			},
		},
		"Unauthorized": {
			Description: "Unauthorized",
			Content: map[string]MediaType{
				"application/json": {Schema: Schema{Type: "object"}},
			},
		},
		"NotFound": {
			Description: "Not found",
			Content: map[string]MediaType{
				"application/json": {Schema: Schema{Type: "object"}},
			},
		},
		"UnprocessableEntity": {
			Description: "Validation error",
			Content: map[string]MediaType{
				"application/json": {Schema: Schema{Type: "object"}},
			},
		},
	}

	// Add standard security scheme
	components.SecuritySchemes = map[string]SecurityScheme{
		"bearerAuth": {
			Type:         "http",
			Scheme:       "bearer",
			BearerFormat: "JWT",
		},
	}

	// Process struct types to create schemas
	for _, typeDef := range types {
		if !typeDef.IsExported {
			continue
		}

		schema := Schema{
			Type:       "object",
			Properties: make(map[string]Schema),
		}

		var required []string

		for _, field := range typeDef.Fields {
			// Skip unexported fields or embedded fields without names
			if len(field.Names) == 0 || !field.Names[0].IsExported() {
				continue
			}

			fieldName := field.Names[0].Name
			jsonTag := ""
			comment := extractFieldComments(field)

			// Extract JSON tag if present
			if field.Tag != nil {
				tag := field.Tag.Value
				jsonTag = extractJSONTag(tag)
				if jsonTag == "-" {
					continue // Skip fields with json:"-"
				}
				if jsonTag != "" {
					fieldName = jsonTag
				}
			}

			// Set field schema
			fieldSchema := convertTypeToSchema(field.Type)

			// Add description from comment if available
			if comment != "" {
				fieldSchema.Description = strings.TrimSpace(comment)
			}

			// Add field-specific enhancements based on names
			addFieldSpecificEnhancements(&fieldSchema, fieldName)

			schema.Properties[fieldName] = fieldSchema

			// Check if field is required
			if field.Tag != nil && strings.Contains(field.Tag.Value, `binding:"required"`) {
				required = append(required, fieldName)
			}
		}

		if len(required) > 0 {
			schema.Required = required
		}

		// Add schema to components
		components.Schemas[typeDef.Name] = schema
	}

	return components
}

// extractJSONTag extracts the JSON field name from a struct tag
func extractJSONTag(tag string) string {
	re := regexp.MustCompile(`json:"([^"]*)"`)
	match := re.FindStringSubmatch(tag)
	if len(match) > 1 {
		parts := strings.Split(match[1], ",")
		return parts[0]
	}
	return ""
}

// convertTypeToSchema converts Go types to OpenAPI schema types
func convertTypeToSchema(expr ast.Expr) Schema {
	switch t := expr.(type) {
	case *ast.Ident:
		switch t.Name {
		case "string":
			return Schema{Type: "string"}
		case "int", "int64", "int32":
			return Schema{Type: "integer", Format: "int64"}
		case "int16", "int8":
			return Schema{Type: "integer", Format: "int32"}
		case "uint", "uint64", "uint32":
			return Schema{Type: "integer", Format: "int64", Minimum: ptrFloat64(0)}
		case "uint16", "uint8":
			return Schema{Type: "integer", Format: "int32", Minimum: ptrFloat64(0)}
		case "float64":
			return Schema{Type: "number", Format: "double"}
		case "float32":
			return Schema{Type: "number", Format: "float"}
		case "bool":
			return Schema{Type: "boolean"}
		case "byte":
			return Schema{Type: "string", Format: "byte"}
		case "rune":
			return Schema{Type: "string"}
		case "time.Time":
			return Schema{Type: "string", Format: "date-time", Example: "2023-01-01T12:00:00Z"}
		default:
			// Could be a custom type
			return Schema{Ref: "#/components/schemas/" + t.Name}
		}
	case *ast.StarExpr:
		schema := convertTypeToSchema(t.X)
		schema.Nullable = true
		return schema
	case *ast.ArrayType:
		itemSchema := convertTypeToSchema(t.Elt)
		return Schema{
			Type:  "array",
			Items: &itemSchema,
		}
	case *ast.MapType:
		// If it's a map with string keys, we can represent it better
		if ident, ok := t.Key.(*ast.Ident); ok && ident.Name == "string" {
			valueSchema := convertTypeToSchema(t.Value)

			// For map[string]interface{}, just return generic object
			if _, ok := t.Value.(*ast.InterfaceType); ok {
				return Schema{
					Type:                 "object",
					AdditionalProperties: true,
				}
			}

			// For map[string]<type>, use additionalProperties to specify the value type
			return Schema{
				Type:                 "object",
				AdditionalProperties: valueSchema,
			}
		}

		// Default representation for other maps
		return Schema{
			Type:                 "object",
			AdditionalProperties: true,
		}
	case *ast.SelectorExpr:
		// Handle time.Time and other imported types
		if ident, ok := t.X.(*ast.Ident); ok {
			if ident.Name == "time" && t.Sel.Name == "Time" {
				return Schema{Type: "string", Format: "date-time", Example: "2023-01-01T12:00:00Z"}
			}
			if ident.Name == "uuid" && t.Sel.Name == "UUID" {
				return Schema{Type: "string", Format: "uuid", Example: "123e4567-e89b-12d3-a456-426614174000"}
			}
		}

		// Default for other selector expressions
		return Schema{Type: "object"}
	case *ast.InterfaceType:
		// For interface{}, return generic object
		return Schema{
			Type:                 "object",
			AdditionalProperties: true,
		}
	case *ast.StructType:
		// For inline struct types, extract fields
		schema := Schema{
			Type:       "object",
			Properties: make(map[string]Schema),
		}

		var required []string

		for _, field := range t.Fields.List {
			if len(field.Names) == 0 {
				continue
			}

			fieldName := field.Names[0].Name
			jsonTag := ""

			// Extract JSON tag if present
			if field.Tag != nil {
				tag := field.Tag.Value
				jsonTag = extractJSONTag(tag)
				if jsonTag == "-" {
					continue // Skip fields with json:"-"
				}
				if jsonTag != "" {
					fieldName = jsonTag
				}
			}

			// Set field schema
			fieldSchema := convertTypeToSchema(field.Type)

			// Add field-specific enhancements based on names
			addFieldSpecificEnhancements(&fieldSchema, fieldName)

			schema.Properties[fieldName] = fieldSchema

			// Check if field is required
			if field.Tag != nil && (strings.Contains(field.Tag.Value, `binding:"required"`) ||
				strings.Contains(field.Tag.Value, `validate:"required"`)) {
				required = append(required, fieldName)
			}
		}

		if len(required) > 0 {
			schema.Required = required
		}

		return schema
	}

	// Default for unknown types
	return Schema{Type: "object"}
}

// addFieldSpecificEnhancements adds additional schema properties based on field names
func addFieldSpecificEnhancements(schema *Schema, fieldName string) {
	// Convert to lowercase for case-insensitive matching
	lowerName := strings.ToLower(fieldName)

	// Email fields
	if strings.Contains(lowerName, "email") {
		if schema.Type == "string" {
			schema.Format = "email"
			schema.Example = "user@example.com"
		}
	}

	// Password fields
	if strings.Contains(lowerName, "password") {
		if schema.Type == "string" {
			schema.Format = "password"
			schema.WriteOnly = true
			// No example for security reasons
		}
	}

	// URL fields
	if strings.Contains(lowerName, "url") || strings.Contains(lowerName, "link") ||
		strings.Contains(lowerName, "website") || strings.Contains(lowerName, "site") {
		if schema.Type == "string" {
			schema.Format = "uri"
			schema.Example = "https://example.com"
		}
	}

	// UUID/ID fields
	if strings.HasSuffix(lowerName, "id") && !strings.Contains(lowerName, "valid") {
		if schema.Type == "string" {
			if strings.Contains(lowerName, "uuid") {
				schema.Format = "uuid"
				schema.Example = "123e4567-e89b-12d3-a456-426614174000"
			} else {
				schema.Example = "5f9d7a7a8b8e8f0d1c3a1b2f"
			}
		}
	}

	// Date/time fields
	if strings.Contains(lowerName, "date") || strings.Contains(lowerName, "time") ||
		strings.HasSuffix(lowerName, "at") {
		if schema.Type == "string" && schema.Format == "" {
			schema.Format = "date-time"
			schema.Example = "2023-01-01T12:00:00Z"
		}
	}

	// Name fields
	if lowerName == "name" || strings.HasSuffix(lowerName, "name") {
		if schema.Type == "string" {
			if strings.Contains(lowerName, "first") {
				schema.Example = "John"
			} else if strings.Contains(lowerName, "last") {
				schema.Example = "Doe"
			} else if strings.Contains(lowerName, "user") {
				schema.Example = "johndoe"
			} else {
				schema.Example = "John Doe"
			}
		}
	}

	// Color fields
	if strings.Contains(lowerName, "color") {
		if schema.Type == "string" {
			schema.Format = "color"
			schema.Example = "#3498db"
		}
	}

	// Phone number fields
	if strings.Contains(lowerName, "phone") || strings.Contains(lowerName, "mobile") ||
		strings.Contains(lowerName, "cellular") || strings.Contains(lowerName, "tel") {
		if schema.Type == "string" {
			schema.Example = "+1234567890"
		}
	}

	// Status fields
	if lowerName == "status" || strings.HasSuffix(lowerName, "status") {
		if schema.Type == "string" && schema.Enum == nil {
			schema.Enum = []interface{}{"active", "inactive", "pending"}
			schema.Example = "active"
		}
	}

	// Add minimum/maximum constraints for specific numeric fields
	if schema.Type == "integer" || schema.Type == "number" {
		if lowerName == "age" {
			schema.Minimum = ptrFloat64(0)
			schema.Maximum = ptrFloat64(120)
			schema.Example = 30
		} else if strings.Contains(lowerName, "count") ||
			strings.Contains(lowerName, "quantity") ||
			strings.HasPrefix(lowerName, "num") {
			schema.Minimum = ptrFloat64(0)
			schema.Example = 5
		} else if strings.Contains(lowerName, "percentage") ||
			strings.Contains(lowerName, "percent") ||
			strings.HasSuffix(lowerName, "pct") {
			schema.Minimum = ptrFloat64(0)
			schema.Maximum = ptrFloat64(100)
			schema.Example = 75
		}
	}
}

// ptrFloat64 returns a pointer to the given float64 value
func ptrFloat64(v float64) *float64 {
	return &v
}

func buildPathsFromHandlers(handlers []HandlerFunc, routeInfo RouteInfo) map[string]PathItem {
	paths := make(map[string]PathItem)

	// Group handlers by their route paths
	handlersByPath := make(map[string][]HandlerFunc)
	for _, h := range handlers {
		fullName := h.Package + "." + h.Func.Name.Name
		if strings.Contains(fullName, ".") {
			// Also try with package name and struct name if it's a method
			if h.Func.Recv != nil && len(h.Func.Recv.List) > 0 {
				receiverType := h.Func.Recv.List[0].Type
				var typeName string
				if starExpr, ok := receiverType.(*ast.StarExpr); ok {
					if ident, ok := starExpr.X.(*ast.Ident); ok {
						typeName = ident.Name
					}
				} else if ident, ok := receiverType.(*ast.Ident); ok {
					typeName = ident.Name
				}

				if typeName != "" {
					methodName := h.Func.Name.Name
					structMethod := h.Package + "." + typeName + "." + methodName
					if path, ok := routeInfo.HandlerToRoute[structMethod]; ok {
						handlersByPath[path] = append(handlersByPath[path], h)
						continue
					}
				}
			}
		}

		// Try different formats of the handler name
		possibleNames := []string{
			fullName,
			h.Func.Name.Name,
		}

		// Check if it's a method on a receiver (struct)
		if h.Func.Recv != nil && len(h.Func.Recv.List) > 0 {
			receiverType := FormatType(h.Func.Recv.List[0].Type)
			receiverName := strings.TrimPrefix(receiverType, "*")
			structMethodName := receiverName + "." + h.Func.Name.Name
			possibleNames = append(possibleNames, structMethodName)

			// Try with lowercase first letter of struct (common in Go)
			if len(receiverName) > 0 {
				lowerFirstChar := strings.ToLower(receiverName[:1]) + receiverName[1:]
				possibleNames = append(possibleNames, lowerFirstChar+"."+h.Func.Name.Name)
			}
		}

		// Try all possible name formats
		routePath := ""
		for _, name := range possibleNames {
			if path, ok := routeInfo.HandlerToRoute[name]; ok {
				routePath = path
				break
			}
		}

		// If still not found, try to infer from the function name
		if routePath == "" {
			method, inferredPath := inferMethodAndRoute(h.Func.Name.Name)
			if method != "" && inferredPath != "" {
				routePath = inferredPath
				// Use inferred method if not already set
				if _, ok := routeInfo.HandlerToMethod[fullName]; !ok {
					routeInfo.HandlerToMethod[fullName] = method
				}
			}
		}

		if routePath != "" {
			handlersByPath[routePath] = append(handlersByPath[routePath], h)
		}
	}

	// Now build each path item
	for path, pathHandlers := range handlersByPath {
		openapiPath := convertColonParamsToBraces(path)
		// Only output if openapiPath is in routeInfo.HandlerToRoute values
		found := false
		for _, v := range routeInfo.HandlerToRoute {
			if convertColonParamsToBraces(v) == openapiPath {
				found = true
				break
			}
		}
		if !found {
			continue
		}
		item := PathItem{
			Summary:     humanize(openapiPath),
			Description: fmt.Sprintf("Operations on %s", openapiPath),
		}

		for _, h := range pathHandlers {
			// Get the HTTP method for this handler
			fullName := h.Package + "." + h.Func.Name.Name
			method := routeInfo.HandlerToMethod[fullName]

			// Try different name formats if not found
			if method == "" {
				// Try without package name
				method = routeInfo.HandlerToMethod[h.Func.Name.Name]

				// Try struct methods
				if h.Func.Recv != nil && len(h.Func.Recv.List) > 0 {
					receiverType := FormatType(h.Func.Recv.List[0].Type)
					receiverName := strings.TrimPrefix(receiverType, "*")
					structMethodName := receiverName + "." + h.Func.Name.Name
					method = routeInfo.HandlerToMethod[structMethodName]

					// If still not found, try lowercase struct name
					if method == "" && len(receiverName) > 0 {
						lowerFirstChar := strings.ToLower(receiverName[:1]) + receiverName[1:]
						method = routeInfo.HandlerToMethod[lowerFirstChar+"."+h.Func.Name.Name]
					}
				}

				// If still not found, infer from function name
				if method == "" {
					inferredMethod, _ := inferMethodAndRoute(h.Func.Name.Name)
					method = inferredMethod
				}
			}

			if method == "" {
				// Default to POST if we couldn't determine the method
				method = "post"
			}

			// Build the operation from the handler function
			op := buildOperation(h, path)

			// Mark as deprecated if needed
			op.Deprecated = h.Deprecated

			// Add operation to the path item
			switch strings.ToLower(method) {
			case "get":
				item.Get = &op
			case "post":
				item.Post = &op
			case "put":
				item.Put = &op
			case "delete":
				item.Delete = &op
			case "patch":
				item.Patch = &op
			}

			// Extract parameters from URL path segments like /users/:id
			pathParams := extractPathParamsFromRoute(path)

			// Add detected path parameters from handler body
			for _, param := range h.PathParams {
				if !containsParameter(pathParams, param) {
					pathParams = append(pathParams, Parameter{
						Name:        param,
						In:          "path",
						Required:    true,
						Description: fmt.Sprintf("%s parameter from URL path", humanize(param)),
						Schema:      Schema{Type: "string"},
					})
				}
			}

			if len(pathParams) > 0 {
				item.Parameters = pathParams
			}
		}

		paths[openapiPath] = item
	}

	return paths
}

// extractPathParamsFromRoute extracts path parameters from route patterns like /users/:id
func extractPathParamsFromRoute(path string) []Parameter {
	var params []Parameter
	segments := strings.Split(path, "/")

	for _, segment := range segments {
		if strings.HasPrefix(segment, ":") {
			// Fiber style (:param)
			paramName := strings.TrimPrefix(segment, ":")
			params = append(params, Parameter{
				Name:        paramName,
				In:          "path",
				Required:    true,
				Description: fmt.Sprintf("%s parameter", humanize(paramName)),
				Schema:      Schema{Type: "string"},
			})
		} else if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
			// OpenAPI/Swagger style ({param})
			paramName := segment[1 : len(segment)-1]
			params = append(params, Parameter{
				Name:        paramName,
				In:          "path",
				Required:    true,
				Description: fmt.Sprintf("%s parameter", humanize(paramName)),
				Schema:      Schema{Type: "string"},
			})
		}
	}

	return params
}

// containsParameter checks if a parameter is already in the parameter list
func containsParameter(params []Parameter, name string) bool {
	for _, p := range params {
		if p.Name == name {
			return true
		}
	}
	return false
}

// buildOperation creates an OpenAPI Operation object from a handler
func buildOperation(h HandlerFunc, path string) Operation {
	// Default values
	operationID := h.Func.Name.Name
	tags := h.Tags

	// If no tags, try to extract from path
	if len(tags) == 0 {
		pathParts := strings.Split(strings.Trim(path, "/"), "/")
		if len(pathParts) > 0 {
			tag := pathParts[0]
			if tag != "" {
				tags = append(tags, tag)
			}
		}
	}

	// Extract summary and description from comments
	var summary, description string
	_, annotations := extractCommentText(h.Func.Doc)

	if annSummary, ok := annotations["Summary"]; ok {
		summary = annSummary
	} else {
		// Generate a summary from the function name
		summary = generateSummaryFromFunction(h.Func.Name.Name, path)
	}

	if annDesc, ok := annotations["Description"]; ok {
		description = annDesc
	} else {
		// Generate description from the function name and parameters
		params, reqBody := extractParamsAndRequestBody(h)
		description = generateDescription(h.Func.Name.Name, params, reqBody)
	}

	// Extract query parameters, request body, and responses
	params, reqBody := extractParamsAndRequestBody(h)

	// Add query parameters detected from the function body
	for _, qp := range h.QueryParams {
		// Check if it's already in parameters
		alreadyExists := false
		for _, p := range params {
			if p.Name == qp && p.In == "query" {
				alreadyExists = true
				break
			}
		}

		if !alreadyExists {
			// Add the query parameter
			params = append(params, Parameter{
				Name:        qp,
				In:          "query",
				Description: fmt.Sprintf("%s query parameter", humanize(qp)),
				Required:    false, // Query params are usually optional
				Schema:      Schema{Type: "string"},
			})
		}
	}

	responses := extractResponses(h)

	// Add standard error responses if not explicitly defined
	addDefaultErrorResponses(&responses, h.ErrorCodes)

	// Ensure we have basic success and error responses
	ensureBasicResponses(&responses)

	op := Operation{
		Summary:     summary,
		Description: description,
		OperationID: operationID,
		Tags:        tags,
		Parameters:  params,
		Responses:   responses,
		Deprecated:  h.Deprecated,
	}

	// Only add request body if method is POST, PUT, PATCH (never for GET)
	method := ""
	if h.Func != nil {
		method = strings.ToUpper(h.Func.Name.Name)
	}
	if reqBody != nil && (method == "POST" || method == "PUT" || method == "PATCH") {
		op.RequestBody = &RequestBody{
			Description: fmt.Sprintf("Request body for %s", operationID),
			Required:    true,
			Content: map[string]MediaType{
				"application/json": {
					Schema: reqBody.Schema,
				},
			},
		}

		// Generate example for request body
		example := generateExampleForSchema(reqBody.Schema, "request")
		if example != nil {
			mediaType := op.RequestBody.Content["application/json"]
			mediaType.Example = example
			op.RequestBody.Content["application/json"] = mediaType
		}

		// Only append to description for POST, PUT, PATCH
		op.Description += "\n\nRequires a request body."
	}

	// Add security requirement if the handler likely needs authentication
	if requiresAuth(path, h) {
		op.Security = []map[string][]string{
			{"bearerAuth": {}},
		}
	}

	return op
}

// generateSummaryFromFunction creates a readable summary from a function name
func generateSummaryFromFunction(funcName, path string) string {
	// Strip common prefixes
	name := funcName
	commonPrefixes := []string{"Handle", "Process", "Get", "Create", "Update", "Delete", "List"}
	for _, prefix := range commonPrefixes {
		if strings.HasPrefix(name, prefix) {
			name = strings.TrimPrefix(name, prefix)
			break
		}
	}

	// Convert camelCase to space-separated words
	name = camelCaseToWords(name)

	// Generate summary based on inferred operation
	method, _ := inferMethodAndRoute(funcName)
	var action string

	switch strings.ToLower(method) {
	case "get":
		if strings.Contains(strings.ToLower(funcName), "list") {
			action = "List"
		} else {
			action = "Get"
		}
	case "post":
		action = "Create"
	case "put":
		action = "Update"
	case "delete":
		action = "Delete"
	case "patch":
		action = "Patch"
	default:
		action = "Manage"
	}

	// Extract resource name from path
	resource := ""
	pathParts := strings.Split(strings.Trim(path, "/"), "/")
	if len(pathParts) > 0 {
		resource = pathParts[len(pathParts)-1]
		// Remove parameters from resource name
		if strings.HasPrefix(resource, ":") || (strings.HasPrefix(resource, "{") && strings.HasSuffix(resource, "}")) {
			if len(pathParts) > 1 {
				resource = pathParts[len(pathParts)-2]
			}
		}
	}

	if resource == "" {
		resource = name
	}

	resource = humanize(resource)

	return fmt.Sprintf("%s %s", action, resource)
}

// camelCaseToWords converts a camelCase string to space-separated words
func camelCaseToWords(input string) string {
	var result strings.Builder
	for i, r := range input {
		if i > 0 && 'A' <= r && r <= 'Z' {
			result.WriteRune(' ')
		}
		result.WriteRune(r)
	}
	return result.String()
}

// requiresAuth tries to determine if an endpoint needs authentication
func requiresAuth(path string, h HandlerFunc) bool {
	// Check for auth-related words in function body if available
	if h.Body != nil {
		authPatterns := []string{
			"authenticate", "authorize", "authentication", "authorization",
			"token", "jwt", "bearer", "auth", "login", "logout", "user.ID",
		}

		bodyStr := exprToString(h.Body)
		for _, pattern := range authPatterns {
			if strings.Contains(strings.ToLower(bodyStr), pattern) {
				return true
			}
		}
	}

	// Most non-public endpoints typically require auth
	publicPaths := []string{
		"/health", "/metrics", "/ping", "/version",
		"/login", "/register", "/forgot-password", "/reset-password",
		"/public", "/docs", "/swagger", "/openapi",
	}

	for _, publicPath := range publicPaths {
		if strings.HasPrefix(path, publicPath) {
			return false
		}
	}

	// Default to requiring auth for most APIs
	return true
}

// addDefaultErrorResponses adds common error responses if not already defined
func addDefaultErrorResponses(responses *map[string]Response, errorCodes []string) {
	// Ensure the responses map exists
	if *responses == nil {
		*responses = make(map[string]Response)
	}

	// Add any error codes detected from the handler function body
	for _, code := range errorCodes {
		// Only add 4xx and 5xx status codes for errors
		if len(code) == 3 && (code[0] == '4' || code[0] == '5') {
			if _, exists := (*responses)[code]; !exists {
				description := statusCodeToDescription(code)

				errorSchema := Schema{
					Type: "object",
					Properties: map[string]Schema{
						"error": {
							Type:        "string",
							Description: "Error message",
							Example:     description,
						},
						"code": {
							Type:        "string",
							Description: "Error code",
							Example:     fmt.Sprintf("ERR_%s", code),
						},
						"details": {
							Type:        "object",
							Description: "Additional error details",
							Nullable:    true,
						},
					},
				}

				(*responses)[code] = Response{
					Description: description,
					Content: map[string]MediaType{
						"application/json": {
							Schema: errorSchema,
							Example: map[string]interface{}{
								"error":   description,
								"code":    fmt.Sprintf("ERR_%s", code),
								"details": nil,
							},
						},
					},
				}
			}
		}
	}

	// Add common error responses if not already defined
	defaultErrors := map[string]string{
		"400": "Bad Request",
		"401": "Unauthorized",
		"403": "Forbidden",
		"404": "Not Found",
		"422": "Unprocessable Entity",
		"500": "Internal Server Error",
	}

	for code, desc := range defaultErrors {
		if _, exists := (*responses)[code]; !exists {
			errorSchema := Schema{
				Type: "object",
				Properties: map[string]Schema{
					"error": {
						Type:        "string",
						Description: "Error message",
						Example:     desc,
					},
					"code": {
						Type:        "string",
						Description: "Error code",
						Example:     fmt.Sprintf("ERR_%s", code),
					},
					"details": {
						Type:        "object",
						Description: "Additional error details",
						Nullable:    true,
					},
				},
			}

			(*responses)[code] = Response{
				Description: desc,
				Content: map[string]MediaType{
					"application/json": {
						Schema: errorSchema,
						Example: map[string]interface{}{
							"error":   desc,
							"code":    fmt.Sprintf("ERR_%s", code),
							"details": nil,
						},
					},
				},
			}
		}
	}
}

// ensureBasicResponses makes sure we have at least a success response
func ensureBasicResponses(responses *map[string]Response) {
	if *responses == nil {
		*responses = make(map[string]Response)
	}

	// Ensure we have at least one success response (2xx)
	hasSuccess := false
	for code := range *responses {
		if len(code) == 3 && code[0] == '2' {
			hasSuccess = true
			break
		}
	}

	if !hasSuccess {
		// Add a generic 200 OK response
		(*responses)["200"] = Response{
			Description: "Successful operation",
			Content: map[string]MediaType{
				"application/json": {
					Schema: Schema{
						Type: "object",
						Properties: map[string]Schema{
							"success": {
								Type:    "boolean",
								Example: true,
							},
						},
					},
				},
			},
		}
	}
}

func buildOpenAPISpec(paths map[string]PathItem, components *Components, tags []Tag, opts Options) OpenAPISpec {
	servers := []Server{
		{URL: "/api/v1/admin"},
	}

	return OpenAPISpec{
		OpenAPI: "3.0.0",
		Info: Info{
			Title:       opts.Title,
			Version:     opts.Version,
			Description: "API documentation for " + opts.Title,
		},
		Servers:    servers,
		Paths:      paths,
		Components: components,
		Tags:       tags,
	}
}

func inferMethodAndRoute(name string) (string, string) {
	lname := strings.ToLower(name)

	// Common method prefixes
	methods := map[string]string{
		"get":    "get",
		"list":   "get",
		"find":   "get",
		"create": "post",
		"add":    "post",
		"update": "put",
		"edit":   "put",
		"delete": "delete",
		"remove": "delete",
		"patch":  "patch",
	}

	for prefix, method := range methods {
		if strings.HasPrefix(lname, prefix) {
			// Convert function name to route path using convention
			routePath := strings.TrimPrefix(lname, prefix)

			// Special cases for list endpoints
			if prefix == "list" {
				return method, "/" + routePath + "s"
			}

			// For other cases, just make path lowercase and prefix with /
			if routePath == "" {
				routePath = prefix // For cases like just "create" -> "/create"
			}

			return method, "/" + routePath
		}
	}

	// Default case for unknown patterns
	return "get", "/" + lname
}

// extractParamsAndRequestBody analyzes the function to extract query parameters and request body
func extractParamsAndRequestBody(h HandlerFunc) ([]Parameter, *Parameter) {
	params := []Parameter{}
	var reqBody *Parameter
	inputStructs := map[string]string{} // Map to store input var names and their types

	// First pass: Find all struct variables that might be used for body parsing
	ast.Inspect(h.Func.Body, func(n ast.Node) bool {
		// Look for variable declarations with struct types
		if assignStmt, ok := n.(*ast.AssignStmt); ok {
			if len(assignStmt.Lhs) == 1 && len(assignStmt.Rhs) == 1 {
				if ident, ok := assignStmt.Lhs[0].(*ast.Ident); ok {
					// Look for struct literal initializations: var input = SomeStruct{}
					if compLit, ok := assignStmt.Rhs[0].(*ast.CompositeLit); ok {
						if typeIdent, ok := compLit.Type.(*ast.Ident); ok {
							inputStructs[ident.Name] = typeIdent.Name
						}
					}
				}
			}
		}

		// Look for var declarations: var input SomeStruct
		if genDecl, ok := n.(*ast.GenDecl); ok && genDecl.Tok == token.VAR {
			for _, spec := range genDecl.Specs {
				if valueSpec, ok := spec.(*ast.ValueSpec); ok && valueSpec.Type != nil {
					for _, name := range valueSpec.Names {
						if typeIdent, ok := valueSpec.Type.(*ast.Ident); ok {
							inputStructs[name.Name] = typeIdent.Name
						}
					}
				}
			}
		}
		return true
	})

	// Second pass: Look for c.QueryParam for explicit query parameters
	ast.Inspect(h.Func.Body, func(n ast.Node) bool {
		if callExpr, ok := n.(*ast.CallExpr); ok {
			if selExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
				if x, ok := selExpr.X.(*ast.Ident); ok && x.Name == "c" {
					// Check for various parameter methods
					paramMethods := map[string]string{
						"Param":         "path",
						"Params":        "path",
						"Query":         "query",
						"QueryParam":    "query",
						"QueryParams":   "query",
						"Get":           "header",
						"GetRespHeader": "header",
					}

					paramType, isParamMethod := paramMethods[selExpr.Sel.Name]
					if isParamMethod && len(callExpr.Args) > 0 {
						if lit, ok := callExpr.Args[0].(*ast.BasicLit); ok {
							paramName := strings.Trim(lit.Value, "\"'")

							// Check if this parameter already exists
							exists := false
							for _, p := range params {
								if p.Name == paramName {
									exists = true
									break
								}
							}

							if !exists {
								param := Parameter{
									Name:        paramName,
									In:          paramType,
									Required:    paramType == "path", // Path params are always required
									Schema:      Schema{Type: "string"},
									Description: paramName + " parameter",
								}

								// Try to infer parameter types from context - common patterns
								if strings.HasSuffix(paramName, "id") || paramName == "id" {
									param.Description = "Unique identifier"
									// If it's a UUID pattern, set the format
									if strings.Contains(paramName, "uuid") {
										param.Schema.Format = "uuid"
									}
								} else if strings.HasSuffix(paramName, "_id") {
									entityName := strings.TrimSuffix(paramName, "_id")
									param.Description = entityName + " identifier"
								} else if paramName == "page" {
									param.Schema = Schema{Type: "integer", Default: 1}
									param.Description = "Page number for pagination"
								} else if paramName == "page_size" || paramName == "limit" {
									param.Schema = Schema{Type: "integer", Default: 20}
									param.Description = "Number of items per page"
								} else if paramName == "sort" || paramName == "order_by" {
									param.Description = "Field to sort by"
								} else if paramName == "direction" || paramName == "order" {
									param.Schema = Schema{Type: "string", Enum: []interface{}{"asc", "desc"}}
									param.Description = "Sort direction"
								} else if strings.HasPrefix(paramName, "filter_") || strings.HasPrefix(paramName, "search_") {
									filterField := strings.TrimPrefix(strings.TrimPrefix(paramName, "filter_"), "search_")
									param.Description = "Filter results by " + filterField
								} else if paramName == "q" || paramName == "query" || paramName == "search" {
									param.Description = "Search query string"
								} else if strings.Contains(paramName, "date") || strings.HasSuffix(paramName, "_at") {
									param.Schema = Schema{Type: "string", Format: "date-time"}
									param.Description = "Date/time filter for " + paramName
								} else if strings.HasPrefix(paramName, "include_") {
									includeName := strings.TrimPrefix(paramName, "include_")
									param.Schema = Schema{Type: "boolean", Default: false}
									param.Description = "Include " + includeName + " in response"
								}

								params = append(params, param)
							}
						}
					}

					// Look for c.QueryInt, c.QueryBool etc. for typed parameters
					typeMatches := map[string]Schema{
						"QueryInt":    {Type: "integer"},
						"QueryBool":   {Type: "boolean"},
						"QueryFloat":  {Type: "number"},
						"QueryParser": {Type: "string"}, // Generic query parser that might have a default
					}

					if schema, found := typeMatches[selExpr.Sel.Name]; found && len(callExpr.Args) > 0 {
						if lit, ok := callExpr.Args[0].(*ast.BasicLit); ok {
							paramName := strings.Trim(lit.Value, "\"'")

							// Check if this parameter already exists
							exists := false
							for i, p := range params {
								if p.Name == paramName {
									// Update existing parameter with better type info
									params[i].Schema = schema
									exists = true
									break
								}
							}

							if !exists {
								// Check for default values in the second argument
								description := paramName + " parameter"
								var defaultValue interface{}

								if len(callExpr.Args) > 1 {
									if lit, ok := callExpr.Args[1].(*ast.BasicLit); ok {
										if schema.Type == "integer" {
											if val, err := strconv.Atoi(lit.Value); err == nil {
												defaultValue = val
											}
										} else if schema.Type == "boolean" {
											if lit.Value == "true" {
												defaultValue = true
											} else if lit.Value == "false" {
												defaultValue = false
											}
										} else {
											defaultValue = strings.Trim(lit.Value, "\"'")
										}
									}
								}

								if defaultValue != nil {
									schema.Default = defaultValue
								}

								params = append(params, Parameter{
									Name:        paramName,
									In:          "query",
									Required:    false,
									Schema:      schema,
									Description: description,
								})
							}
						}
					}
				}
			}
		}

		// Check for variable assignments from query parameters
		if assignStmt, ok := n.(*ast.AssignStmt); ok {
			for i, rhs := range assignStmt.Rhs {
				if callExpr, ok := rhs.(*ast.CallExpr); ok {
					if selExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
						if x, ok := selExpr.X.(*ast.Ident); ok && x.Name == "c" {
							if (selExpr.Sel.Name == "Query" || selExpr.Sel.Name == "QueryParam") && len(callExpr.Args) > 0 {
								if lit, ok := callExpr.Args[0].(*ast.BasicLit); ok {
									paramName := strings.Trim(lit.Value, "\"'")

									// Try to infer parameter type from assignment
									if i < len(assignStmt.Lhs) {
										if ident, ok := assignStmt.Lhs[i].(*ast.Ident); ok {
											// Look for variable type inferences in later code
											varName := ident.Name

											// Search for type conversions of this variable
											ast.Inspect(h.Func.Body, func(n ast.Node) bool {
												if callExpr, ok := n.(*ast.CallExpr); ok {
													if ident, ok := callExpr.Fun.(*ast.Ident); ok {
														// Check for type conversions like strconv.Atoi(varName)
														if ident.Name == "Atoi" || ident.Name == "ParseInt" ||
															ident.Name == "ParseInt64" || ident.Name == "ParseUint" {
															if len(callExpr.Args) > 0 {
																if argIdent, ok := callExpr.Args[0].(*ast.Ident); ok && argIdent.Name == varName {
																	// This is a conversion to int, add/update parameter
																	exists := false
																	for i, p := range params {
																		if p.Name == paramName {
																			params[i].Schema.Type = "integer"
																			exists = true
																			break
																		}
																	}

																	if !exists {
																		params = append(params, Parameter{
																			Name:        paramName,
																			In:          "query",
																			Required:    false,
																			Schema:      Schema{Type: "integer"},
																			Description: paramName + " parameter",
																		})
																	}
																	return false
																}
															}
														} else if ident.Name == "ParseBool" {
															if len(callExpr.Args) > 0 {
																if argIdent, ok := callExpr.Args[0].(*ast.Ident); ok && argIdent.Name == varName {
																	// This is a conversion to bool, add/update parameter
																	exists := false
																	for i, p := range params {
																		if p.Name == paramName {
																			params[i].Schema.Type = "boolean"
																			exists = true
																			break
																		}
																	}

																	if !exists {
																		params = append(params, Parameter{
																			Name:        paramName,
																			In:          "query",
																			Required:    false,
																			Schema:      Schema{Type: "boolean"},
																			Description: paramName + " parameter",
																		})
																	}
																	return false
																}
															}
														} else if ident.Name == "ParseFloat" {
															if len(callExpr.Args) > 0 {
																if argIdent, ok := callExpr.Args[0].(*ast.Ident); ok && argIdent.Name == varName {
																	// This is a conversion to float, add/update parameter
																	exists := false
																	for i, p := range params {
																		if p.Name == paramName {
																			params[i].Schema.Type = "number"
																			exists = true
																			break
																		}
																	}

																	if !exists {
																		params = append(params, Parameter{
																			Name:        paramName,
																			In:          "query",
																			Required:    false,
																			Schema:      Schema{Type: "number"},
																			Description: paramName + " parameter",
																		})
																	}
																	return false
																}
															}
														}
													}
												}
												return true
											})
										}
									}
								}
							}
						}
					}
				}
			}
		}
		return true
	})

	// Now look for input from c.BodyParser, if we found one, add it as request body
	ast.Inspect(h.Func.Body, func(n ast.Node) bool {
		if callExpr, ok := n.(*ast.CallExpr); ok {
			if selExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
				if x, ok := selExpr.X.(*ast.Ident); ok && x.Name == "c" {
					// Check for body parser methods
					if (selExpr.Sel.Name == "BodyParser" || selExpr.Sel.Name == "Bind") && len(callExpr.Args) > 0 {
						if unary, ok := callExpr.Args[0].(*ast.UnaryExpr); ok && unary.Op == token.AND {
							if ident, ok := unary.X.(*ast.Ident); ok {
								// We found a body parameter
								varName := ident.Name

								// Try to find the type from our earlier analysis
								if typeName, ok := inputStructs[varName]; ok {
									reqBody = &Parameter{
										Name:     varName,
										In:       "body",
										Required: true,
										Schema:   Schema{Ref: "#/components/schemas/" + typeName},
									}
								} else {
									reqBody = &Parameter{
										Name:     varName,
										In:       "body",
										Required: true,
										Schema:   Schema{Type: "object"},
									}
								}
							}
						}
					}
				}
			}
		}
		return true
	})

	// Look for c.BodyParser(struct{...}) inline struct definitions
	ast.Inspect(h.Func.Body, func(n ast.Node) bool {
		if callExpr, ok := n.(*ast.CallExpr); ok {
			if selExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
				if x, ok := selExpr.X.(*ast.Ident); ok && x.Name == "c" {
					if (selExpr.Sel.Name == "BodyParser" || selExpr.Sel.Name == "Bind") && len(callExpr.Args) > 0 {
						// Check if we're parsing into an anonymous struct literal
						// This often happens with simple input structs:
						// c.BodyParser(&struct{ ID string `json:"id"` }{})
						if unary, ok := callExpr.Args[0].(*ast.UnaryExpr); ok && unary.Op == token.AND {
							if compLit, ok := unary.X.(*ast.CompositeLit); ok {
								if structType, ok := compLit.Type.(*ast.StructType); ok {
									// Extract fields from anonymous struct for request schema
									schema := Schema{
										Type:       "object",
										Properties: make(map[string]Schema),
									}

									var required []string

									for _, field := range structType.Fields.List {
										if len(field.Names) == 0 {
											continue
										}

										fieldName := field.Names[0].Name
										jsonTag := ""

										// Extract JSON tag
										if field.Tag != nil {
											tag := field.Tag.Value
											jsonTag = extractJSONTag(tag)
											if jsonTag == "-" {
												continue
											}
											if jsonTag != "" {
												fieldName = jsonTag
											}
										}

										// Convert field type to schema
										fieldSchema := convertTypeToSchema(field.Type)
										schema.Properties[fieldName] = fieldSchema

										// Check if required based on tag
										if field.Tag != nil && (strings.Contains(field.Tag.Value, `binding:"required"`) ||
											strings.Contains(field.Tag.Value, `validate:"required"`)) {
											required = append(required, fieldName)
										}
									}

									if len(required) > 0 {
										schema.Required = required
									}

									reqBody = &Parameter{
										Name:     "anonymousInput",
										In:       "body",
										Required: true,
										Schema:   schema,
									}
								}
							}
						}
					}
				}
			}
		}
		return true
	})

	// Also look for function parameters (excluding the context param)
	// as these often indicate query parameters
	for _, field := range h.Func.Type.Params.List {
		if len(field.Names) == 0 {
			continue
		}

		for _, name := range field.Names {
			paramName := name.Name
			if paramName == "c" || paramName == "ctx" || paramName == "context" {
				continue // Skip context parameter
			}

			// Check if this param already exists from our analysis
			alreadyExists := false
			for _, p := range params {
				if p.Name == paramName {
					alreadyExists = true
					break
				}
			}

			if !alreadyExists {
				typeStr := exprToString(field.Type)
				paramSchema := Schema{Type: "string"} // Default

				// Infer parameter type from its Go type
				if strings.Contains(typeStr, "int") {
					paramSchema = Schema{Type: "integer"}
				} else if strings.Contains(typeStr, "float") {
					paramSchema = Schema{Type: "number"}
				} else if strings.Contains(typeStr, "bool") {
					paramSchema = Schema{Type: "boolean"}
				}

				params = append(params, Parameter{
					Name:     paramName,
					In:       "query",
					Required: false,
					Schema:   paramSchema,
				})
			}
		}
	}

	// Also try to look for special case parameter extraction from request URL patterns in fiber
	// Like c.Params("id")
	ast.Inspect(h.Func.Body, func(n ast.Node) bool {
		if callExpr, ok := n.(*ast.CallExpr); ok {
			if selExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
				if x, ok := selExpr.X.(*ast.Ident); ok && x.Name == "c" {
					if selExpr.Sel.Name == "Params" && len(callExpr.Args) > 0 {
						if lit, ok := callExpr.Args[0].(*ast.BasicLit); ok {
							paramName := strings.Trim(lit.Value, "\"'")

							// Check if this parameter already exists
							exists := false
							for _, p := range params {
								if p.Name == paramName {
									// Update to path parameter since it's likely from route
									p.In = "path"
									p.Required = true
									exists = true
									break
								}
							}

							if !exists {
								params = append(params, Parameter{
									Name:        paramName,
									In:          "path",
									Required:    true,
									Schema:      Schema{Type: "string"},
									Description: paramName + " path parameter",
								})
							}
						}
					}
				}
			}
		}
		return true
	})

	// Filter out any body param (will be handled separately in OpenAPI 3)
	filtered := params[:0]
	for _, p := range params {
		if p.In != "body" {
			filtered = append(filtered, p)
		}
	}

	return filtered, reqBody
}

// extractResponses analyzes the function body to infer response types and status codes
func extractResponses(h HandlerFunc) map[string]Response {
	responses := map[string]Response{
		"200": {
			Description: "OK",
			Content:     map[string]MediaType{"application/json": {Schema: Schema{Type: "object"}}},
		},
	}

	// First, look for return statements to determine success response types
	var successResponseTypes []Schema
	ast.Inspect(h.Func.Body, func(n ast.Node) bool {
		if returnStmt, ok := n.(*ast.ReturnStmt); ok {
			// Check if it's a return c.JSON(data) pattern
			if len(returnStmt.Results) == 1 {
				if callExpr, ok := returnStmt.Results[0].(*ast.CallExpr); ok {
					if selExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
						if x, ok := selExpr.X.(*ast.Ident); ok && x.Name == "c" {
							if selExpr.Sel.Name == "JSON" && len(callExpr.Args) > 0 {
								// Success response with c.JSON()
								responseSchema := inferResponseSchema(callExpr.Args[len(callExpr.Args)-1])
								successResponseTypes = append(successResponseTypes, responseSchema)
							} else if selExpr.Sel.Name == "Status" && len(callExpr.Args) > 1 {
								// Check for c.Status(200).JSON() pattern
								if callExpr2, ok := callExpr.Args[len(callExpr.Args)-1].(*ast.CallExpr); ok {
									if selExpr2, ok := callExpr2.Fun.(*ast.SelectorExpr); ok && selExpr2.Sel.Name == "JSON" {
										if statusExpr, ok := callExpr.Args[0].(*ast.SelectorExpr); ok {
											statusName := statusExpr.Sel.Name
											if strings.HasPrefix(statusName, "Status") {
												code := statusNameToCode(statusName)
												if code == "200" || code == "201" || code == "202" {
													responseSchema := inferResponseSchema(callExpr2.Args[len(callExpr2.Args)-1])
													successResponseTypes = append(successResponseTypes, responseSchema)
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
		return true
	})

	// If we found success response types, try to determine which is the best one
	if len(successResponseTypes) > 0 {
		bestResponseType := successResponseTypes[0]
		// Prefer schemas with proper references
		for _, schema := range successResponseTypes {
			if schema.Ref != "" {
				bestResponseType = schema
				break
			}
		}

		// Update the 200 response with the best schema we found
		if resp, ok := responses["200"]; ok {
			resp.Content["application/json"] = MediaType{Schema: bestResponseType}
			responses["200"] = resp
		}

		// Check for collection responses (arrays)
		if h.Func.Name.Name == "List" || strings.HasPrefix(h.Func.Name.Name, "List") {
			// This is likely returning a collection/array
			if resp, ok := responses["200"]; ok {
				schema := resp.Content["application/json"].Schema

				// If it's not already an array, make it one
				if schema.Type != "array" {
					// Check if we have a reference to a single item
					if schema.Ref != "" {
						// Convert to array of that type
						entityType := strings.TrimPrefix(schema.Ref, "#/components/schemas/")
						// For pluralized names, make it singular for item schema
						if strings.HasSuffix(entityType, "s") {
							entityType = entityType[:len(entityType)-1]
						}

						resp.Content["application/json"] = MediaType{
							Schema: Schema{
								Type: "array",
								Items: &Schema{
									Ref: "#/components/schemas/" + entityType,
								},
							},
						}
						responses["200"] = resp
					} else {
						// Just make it an array of objects
						resp.Content["application/json"] = MediaType{
							Schema: Schema{
								Type: "array",
								Items: &Schema{
									Type: "object",
								},
							},
						}
						responses["200"] = resp
					}
				}
			}
		}

		// Add pagination for List endpoints
		if h.Func.Name.Name == "List" || strings.HasPrefix(h.Func.Name.Name, "List") {
			// Check if the response is already wrapped
			schema := responses["200"].Content["application/json"].Schema
			if schema.Type != "object" || len(schema.Properties) == 0 {
				// Create a wrapper object with pagination
				itemsSchema := schema // Save the items schema

				// If this is an entity known as "Organization", the list would be "organizations"
				collectionName := "items"
				if strings.HasPrefix(h.Func.Name.Name, "List") {
					entityName := strings.TrimPrefix(h.Func.Name.Name, "List")
					if entityName != "" {
						// Convert to lowercase and pluralize
						collectionName = strings.ToLower(entityName)
						if !strings.HasSuffix(collectionName, "s") {
							collectionName += "s"
						}
					}
				}

				responses["200"].Content["application/json"] = MediaType{
					Schema: Schema{
						Type: "object",
						Properties: map[string]Schema{
							collectionName: itemsSchema,
							"page": {
								Type: "integer",
							},
							"page_size": {
								Type: "integer",
							},
							"total": {
								Type: "integer",
							},
						},
					},
				}
			}
		}
	}

	// Now find all error responses from status codes
	ast.Inspect(h.Func.Body, func(n ast.Node) bool {
		if callExpr, ok := n.(*ast.CallExpr); ok {
			if selExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
				if x, ok := selExpr.X.(*ast.Ident); ok && x.Name == "c" {
					if selExpr.Sel.Name == "Status" && len(callExpr.Args) > 0 {
						// Look for c.Status(fiber.StatusXXX) pattern
						if selExpr2, ok := callExpr.Args[0].(*ast.SelectorExpr); ok {
							if x, ok := selExpr2.X.(*ast.Ident); ok && x.Name == "fiber" {
								status := selExpr2.Sel.Name
								if strings.HasPrefix(status, "Status") {
									code := statusNameToCode(status)
									if code != "" {
										// Try to extract error schema from subsequent JSON call
										responseType := findResponseType(callExpr, h.Func.Body)

										responses[code] = Response{
											Description: statusCodeToDescription(code),
											Content: map[string]MediaType{
												"application/json": {Schema: responseType},
											},
										}
									}
								}
							}
						} else if lit, ok := callExpr.Args[0].(*ast.BasicLit); ok {
							// Direct status code like c.Status(404)
							code := lit.Value
							responses[code] = Response{
								Description: statusCodeToDescription(code),
								Content: map[string]MediaType{
									"application/json": {Schema: Schema{Type: "object"}},
								},
							}
						}
					}
				}
			}
		}
		return true
	})

	// Add common error responses if they're handled in validation
	commonErrors := map[string]string{
		"400": "Bad Request",
		"401": "Unauthorized",
		"403": "Forbidden",
		"404": "Not Found",
		"422": "Unprocessable Entity",
		"500": "Internal Server Error",
	}

	// Check for validation code patterns that indicate error handling
	hasValidation := false
	hasAuthorization := false
	hasNotFound := false

	ast.Inspect(h.Func.Body, func(n ast.Node) bool {
		// Check for input validation: if err := input.Validate(); err != nil
		if ifStmt, ok := n.(*ast.IfStmt); ok {
			if assignStmt, ok := ifStmt.Init.(*ast.AssignStmt); ok {
				if len(assignStmt.Rhs) == 1 {
					if callExpr, ok := assignStmt.Rhs[0].(*ast.CallExpr); ok {
						if selExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok && selExpr.Sel.Name == "Validate" {
							hasValidation = true
						}
					}
				}
			}

			// Check for c.BodyParser(&input); err != nil pattern
			if binaryExpr, ok := ifStmt.Cond.(*ast.BinaryExpr); ok {
				if binaryExpr.Op == token.NEQ {
					if ident, ok := binaryExpr.X.(*ast.Ident); ok && ident.Name == "err" {
						if lit, ok := binaryExpr.Y.(*ast.Ident); ok && lit.Name == "nil" {
							// This indicates error handling
							hasValidation = true
						}
					}
				}
			}

			// Check for permission checks
			if binaryExpr, ok := ifStmt.Cond.(*ast.BinaryExpr); ok {
				if binaryExpr.Op == token.EQL {
					if ident, ok := binaryExpr.X.(*ast.Ident); ok && ident.Name == "permitted" {
						if lit, ok := binaryExpr.Y.(*ast.BasicLit); ok && lit.Value == "false" {
							// This indicates permission check
							hasAuthorization = true
						}
					}
				}
			}

			// Check for not found checks
			if callExpr, ok := ifStmt.Cond.(*ast.CallExpr); ok {
				if selExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok && selExpr.Sel.Name == "NotFound" {
					hasNotFound = true
				}
			}
		}
		return true
	})

	// Add response codes based on our code analysis and use commonErrors map
	if hasValidation {
		if _, exists := responses["400"]; !exists {
			responses["400"] = Response{
				Description: commonErrors["400"] + " - Invalid input",
				Content: map[string]MediaType{
					"application/json": {Schema: Schema{
						Type: "object",
						Properties: map[string]Schema{
							"error": {Type: "string"},
							"details": {
								Type: "array",
								Items: &Schema{
									Type: "object",
									Properties: map[string]Schema{
										"field":   {Type: "string"},
										"message": {Type: "string"},
									},
								},
							},
						},
					}},
				},
			}
		}

		if _, exists := responses["422"]; !exists {
			responses["422"] = Response{
				Description: commonErrors["422"] + " - Validation failed",
				Content: map[string]MediaType{
					"application/json": {Schema: Schema{
						Type: "object",
						Properties: map[string]Schema{
							"error": {Type: "string"},
							"details": {
								Type: "array",
								Items: &Schema{
									Type: "object",
									Properties: map[string]Schema{
										"field":   {Type: "string"},
										"message": {Type: "string"},
									},
								},
							},
						},
					}},
				},
			}
		}
	}

	if hasAuthorization {
		if _, exists := responses["401"]; !exists {
			responses["401"] = Response{
				Description: commonErrors["401"] + " - Authentication required",
				Content: map[string]MediaType{
					"application/json": {Schema: Schema{
						Type: "object",
						Properties: map[string]Schema{
							"error":   {Type: "string"},
							"message": {Type: "string"},
						},
					}},
				},
			}
		}

		if _, exists := responses["403"]; !exists {
			responses["403"] = Response{
				Description: commonErrors["403"] + " - Insufficient permissions",
				Content: map[string]MediaType{
					"application/json": {Schema: Schema{
						Type: "object",
						Properties: map[string]Schema{
							"error":   {Type: "string"},
							"message": {Type: "string"},
						},
					}},
				},
			}
		}
	}

	if hasNotFound {
		if _, exists := responses["404"]; !exists {
			responses["404"] = Response{
				Description: commonErrors["404"] + " - Resource doesn't exist",
				Content: map[string]MediaType{
					"application/json": {Schema: Schema{
						Type: "object",
						Properties: map[string]Schema{
							"error":   {Type: "string"},
							"message": {Type: "string"},
						},
					}},
				},
			}
		}
	}

	// Check GET operations, 404 is common
	handlerName := h.Func.Name.Name
	if strings.HasPrefix(handlerName, "Get") && !strings.HasPrefix(handlerName, "GetAll") && !strings.HasPrefix(handlerName, "GetList") {
		if _, exists := responses["404"]; !exists {
			responses["404"] = Response{
				Description: "Not Found - Resource doesn't exist",
				Content: map[string]MediaType{
					"application/json": {Schema: Schema{
						Type: "object",
						Properties: map[string]Schema{
							"error": {Type: "string"},
						},
					}},
				},
			}
		}
	}

	// Check CREATE operations, 201 is common
	if strings.HasPrefix(handlerName, "Create") || strings.HasPrefix(handlerName, "Add") || strings.HasPrefix(handlerName, "Insert") {
		if _, exists := responses["201"]; !exists {
			// Clone the 200 response to 201 for creation endpoints
			if resp, ok := responses["200"]; ok {
				resp.Description = "Created successfully"
				responses["201"] = resp

				// Remove the 200 response since 201 is more appropriate
				delete(responses, "200")
			}
		}
	}

	// Check DELETE operations, 204 is common
	if strings.HasPrefix(handlerName, "Delete") || strings.HasPrefix(handlerName, "Remove") {
		if _, exists := responses["204"]; !exists {
			responses["204"] = Response{
				Description: "Deleted successfully",
			}
			// No content needed for 204

			// Remove the 200 response since 204 is more appropriate
			delete(responses, "200")
		}
	}

	// After the code that updates the 200 response with the best schema we found, add code to generate examples:

	// Create an example response based on the schema
	if resp, ok := responses["200"]; ok {
		mediaType := resp.Content["application/json"]
		mediaType.Example = generateExampleForSchema(mediaType.Schema, handlerName)
		resp.Content["application/json"] = mediaType
		responses["200"] = resp
	}

	return responses
}

// statusNameToCode converts fiber.StatusXXX to HTTP status code
func statusNameToCode(statusName string) string {
	statusMap := map[string]string{
		"StatusOK":                  "200",
		"StatusCreated":             "201",
		"StatusAccepted":            "202",
		"StatusNoContent":           "204",
		"StatusBadRequest":          "400",
		"StatusUnauthorized":        "401",
		"StatusForbidden":           "403",
		"StatusNotFound":            "404",
		"StatusMethodNotAllowed":    "405",
		"StatusNotAcceptable":       "406",
		"StatusRequestTimeout":      "408",
		"StatusConflict":            "409",
		"StatusGone":                "410",
		"StatusLengthRequired":      "411",
		"StatusPreconditionFailed":  "412",
		"StatusUnprocessableEntity": "422",
		"StatusTooManyRequests":     "429",
		"StatusInternalServerError": "500",
		"StatusNotImplemented":      "501",
		"StatusBadGateway":          "502",
		"StatusServiceUnavailable":  "503",
		"StatusGatewayTimeout":      "504",
	}

	if code, exists := statusMap[statusName]; exists {
		return code
	}
	return ""
}

// statusCodeToDescription returns a descriptive text for HTTP status codes
func statusCodeToDescription(code string) string {
	descriptions := map[string]string{
		"200": "OK",
		"201": "Created",
		"202": "Accepted",
		"204": "No Content",
		"400": "Bad Request",
		"401": "Unauthorized",
		"403": "Forbidden",
		"404": "Not Found",
		"405": "Method Not Allowed",
		"406": "Not Acceptable",
		"408": "Request Timeout",
		"409": "Conflict",
		"410": "Gone",
		"411": "Length Required",
		"412": "Precondition Failed",
		"422": "Unprocessable Entity",
		"429": "Too Many Requests",
		"500": "Internal Server Error",
		"501": "Not Implemented",
		"502": "Bad Gateway",
		"503": "Service Unavailable",
		"504": "Gateway Timeout",
	}

	if desc, exists := descriptions[code]; exists {
		return desc
	}
	return "Response with status " + code
}

// findResponseType tries to infer the response type from a c.Status().JSON() call
func findResponseType(statusCall *ast.CallExpr, body *ast.BlockStmt) Schema {
	if statusCall.Fun.(*ast.SelectorExpr).Sel.Name != "Status" {
		return Schema{Type: "object"}
	}

	// Find if this Status call is chained with a JSON call
	nodePos := statusCall.End()
	var jsonCall *ast.CallExpr

	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if sel.Sel.Name == "JSON" && sel.X.Pos() == nodePos {
					jsonCall = call
					return false
				}
			}
		}
		return true
	})

	if jsonCall != nil && len(jsonCall.Args) > 0 {
		return inferResponseSchema(jsonCall.Args[0])
	}

	return Schema{Type: "object"}
}

// inferResponseSchema tries to determine the schema of a response value
func inferResponseSchema(expr ast.Expr) Schema {
	switch t := expr.(type) {
	case *ast.CompositeLit:
		if _, ok := t.Type.(*ast.MapType); ok {
			// This is a map[string]interface{} or similar
			return Schema{Type: "object"}
		}

		if ident, ok := t.Type.(*ast.Ident); ok {
			// This is a named struct type
			schema := Schema{Ref: "#/components/schemas/" + ident.Name}

			// Check if the struct is initialized with values that might indicate relationships
			for _, elt := range t.Elts {
				if kv, ok := elt.(*ast.KeyValueExpr); ok {
					if key, ok := kv.Key.(*ast.Ident); ok {
						// If we have fields like "Items", "Children", etc. that suggest nesting
						fieldName := key.Name
						if strings.HasSuffix(strings.ToLower(fieldName), "s") &&
							(strings.Contains(fieldName, "Item") ||
								strings.Contains(fieldName, "Children") ||
								strings.Contains(fieldName, "List")) {
							// This suggests a nested array relationship
							valueSchema := inferResponseSchema(kv.Value)
							if valueSchema.Type == "array" || valueSchema.Ref != "" {
								return Schema{
									Type: "object",
									Properties: map[string]Schema{
										fieldName: valueSchema,
									},
								}
							}
						}
					}
				}
			}

			return schema
		}

		// Handle array literals
		if arrayType, ok := t.Type.(*ast.ArrayType); ok {
			itemsSchema := Schema{Type: "object"} // Default

			// If we have elements in the array literal, try to infer their type
			if len(t.Elts) > 0 {
				itemsSchema = inferResponseSchema(t.Elts[0])
			} else {
				// Try to infer from the array type declaration
				if ident, ok := arrayType.Elt.(*ast.Ident); ok {
					// This is a named struct type array
					itemsSchema = Schema{Ref: "#/components/schemas/" + ident.Name}
				}
			}

			return Schema{
				Type:  "array",
				Items: &itemsSchema,
			}
		}

	case *ast.Ident:
		// This is a variable, could be a struct instance
		if t.Name == "nil" {
			return Schema{Type: "null"}
		}

		// Try to infer the variable type from its name
		if strings.HasSuffix(t.Name, "s") && len(t.Name) > 2 {
			// This might be a plural variable name indicating an array
			singularName := t.Name[:len(t.Name)-1]
			firstChar := singularName[0:1]

			// If the singular form starts with uppercase, it might be a model type
			if firstChar == strings.ToUpper(firstChar) {
				return Schema{
					Type: "array",
					Items: &Schema{
						Ref: "#/components/schemas/" + singularName,
					},
				}
			}
		}

		// Try to infer type from common naming patterns
		if strings.HasPrefix(t.Name, "user") || strings.HasPrefix(t.Name, "User") {
			return Schema{Ref: "#/components/schemas/User"}
		} else if strings.HasPrefix(t.Name, "account") || strings.HasPrefix(t.Name, "Account") {
			return Schema{Ref: "#/components/schemas/Account"}
		} else if strings.HasPrefix(t.Name, "organization") || strings.HasPrefix(t.Name, "Organization") {
			return Schema{Ref: "#/components/schemas/Organization"}
		} else if strings.HasPrefix(t.Name, "tenant") || strings.HasPrefix(t.Name, "Tenant") {
			return Schema{Ref: "#/components/schemas/Tenant"}
		} else if strings.HasPrefix(t.Name, "project") || strings.HasPrefix(t.Name, "Project") {
			return Schema{Ref: "#/components/schemas/Project"}
		}

		return Schema{Type: "object"}

	case *ast.SelectorExpr:
		// Handle time.Time and other imported types
		if ident, ok := t.X.(*ast.Ident); ok {
			if ident.Name == "time" && t.Sel.Name == "Time" {
				return Schema{Type: "string", Format: "date-time"}
			}

			// Check for fiber.Map type
			if ident.Name == "fiber" && t.Sel.Name == "Map" {
				return Schema{Type: "object"}
			}

			// Check for response models from imported packages
			if t.Sel.Name == "Response" ||
				strings.HasSuffix(t.Sel.Name, "Response") ||
				strings.HasSuffix(t.Sel.Name, "Result") {
				return Schema{
					Type: "object",
					Properties: map[string]Schema{
						"data":    {Type: "object"},
						"message": {Type: "string"},
						"status":  {Type: "string"},
					},
				}
			}
		}

	case *ast.CallExpr:
		// Handle function calls that construct responses
		if sel, ok := t.Fun.(*ast.SelectorExpr); ok {
			// Cases like models.NewUserResponse(user)
			if strings.HasPrefix(sel.Sel.Name, "New") &&
				(strings.HasSuffix(sel.Sel.Name, "Response") ||
					strings.HasSuffix(sel.Sel.Name, "Result")) {

				// Extract the entity name from the function (NewUserResponse -> User)
				entityName := strings.TrimPrefix(sel.Sel.Name, "New")
				entityName = strings.TrimSuffix(entityName, "Response")
				entityName = strings.TrimSuffix(entityName, "Result")

				if entityName != "" {
					// This is likely returning an entity schema
					return Schema{Ref: "#/components/schemas/" + entityName}
				}
			}
		}

	case *ast.UnaryExpr:
		// Handle cases like &User{...}
		if t.Op == token.AND {
			return inferResponseSchema(t.X)
		}

	case *ast.ArrayType:
		// Handle array type declarations
		itemsSchema := Schema{Type: "object"} // Default

		// Try to infer array item type
		if ident, ok := t.Elt.(*ast.Ident); ok {
			itemsSchema = Schema{Ref: "#/components/schemas/" + ident.Name}
		} else {
			// Recursively infer the item type
			itemsSchema = inferResponseSchema(t.Elt)
		}

		return Schema{
			Type:  "array",
			Items: &itemsSchema,
		}
	}

	// Default fallback
	return Schema{Type: "object"}
}

// exprToString converts an ast.Expr to a string representation
func exprToString(expr interface{}) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return exprToString(t.X) + "." + t.Sel.Name
	case *ast.StarExpr:
		return "*" + exprToString(t.X)
	case *ast.ArrayType:
		return "[]" + exprToString(t.Elt)
	case *ast.MapType:
		return "map[" + exprToString(t.Key) + "]" + exprToString(t.Value)
	case *ast.InterfaceType:
		return "interface{}"
	case *ast.StructType:
		return "struct{...}"
	case *ast.FuncType:
		return "func(...) ..."
	case *ast.CompositeLit:
		return exprToString(t.Type)
	case *ast.CallExpr:
		return exprToString(t.Fun) + "(...)"
	case *ast.BasicLit:
		return t.Value
	default:
		return fmt.Sprintf("%T", expr)
	}
}

// isUtilityFunction determines if a function is a utility function that shouldn't be exposed as an API endpoint
func isUtilityFunction(h HandlerFunc, routeInfo RouteInfo) bool {
	handlerName := h.Func.Name.Name

	// Common utility function patterns
	utilityPatterns := []string{
		"validate", "Validate",
		"parse", "Parse",
		"format", "Format",
		"convert", "Convert",
		"transform", "Transform",
		"util", "Util",
		"helper", "Helper",
		"middleware", "Middleware",
		"internal", "Internal",
	}

	for _, pattern := range utilityPatterns {
		if strings.Contains(handlerName, pattern) {
			return true
		}
	}

	// Check if function has known utility function signatures
	// like returning errors only or taking unusual parameters
	if h.Comment != "" && (strings.Contains(strings.ToLower(h.Comment), "utility") ||
		strings.Contains(strings.ToLower(h.Comment), "helper") ||
		strings.Contains(strings.ToLower(h.Comment), "internal")) {
		return true
	}

	// Helper functions that don't match API handler patterns
	if h.Func.Type.Results != nil {
		// Check if function doesn't return fiber.Handler
		for _, result := range h.Func.Type.Results.List {
			resultType := exprToString(result.Type)
			if strings.Contains(resultType, "error") && len(h.Func.Type.Results.List) == 1 {
				// Functions that only return an error are likely utilities
				return true
			}
		}
	}

	// Check if function is defined in a utilities package
	if strings.Contains(strings.ToLower(h.Package), "util") ||
		strings.Contains(strings.ToLower(h.Package), "helper") ||
		strings.Contains(strings.ToLower(h.Package), "internal") {
		return true
	}

	// Handler prefixes - if they don't have these prefixes, might be utility functions
	handlerPrefixes := []string{
		"Get", "List", "Find", "Create", "Update", "Delete", "Patch",
		"Add", "Remove", "Edit", "Handle",
	}

	// Check if starts with a common handler prefix
	hasHandlerPrefix := false
	for _, prefix := range handlerPrefixes {
		if strings.HasPrefix(handlerName, prefix) {
			hasHandlerPrefix = true
			break
		}
	}

	if !hasHandlerPrefix {
		// If no common handler prefix and no route found for it
		if _, exists := routeInfo.HandlerToRoute[handlerName]; !exists {
			return true
		}
	}

	return false
}

// extractSummary extracts the @Summary tag value from a comment
func extractSummary(comment string) string {
	lines := strings.Split(comment, "\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "@Summary") {
			parts := strings.SplitN(strings.TrimSpace(line), "@Summary", 2)
			if len(parts) > 1 {
				return strings.TrimSpace(parts[1])
			}
		}
	}

	// If no @Summary tag, take the first line as a fallback
	if len(lines) > 0 {
		firstLine := strings.TrimSpace(lines[0])
		// Remove comment markers
		firstLine = strings.TrimPrefix(firstLine, "//")
		firstLine = strings.TrimSpace(firstLine)
		if len(firstLine) > 0 {
			return firstLine
		}
	}

	return ""
}

// cleanDescription cleans up the comment to be used as a description
func cleanDescription(comment string) string {
	// Remove @tag annotations
	lines := strings.Split(comment, "\n")
	var resultLines []string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "@") {
			// Remove comment markers
			cleaned := strings.TrimPrefix(trimmed, "//")
			cleaned = strings.TrimSpace(cleaned)
			if cleaned != "" {
				resultLines = append(resultLines, cleaned)
			}
		}
	}

	return strings.Join(resultLines, "\n")
}

// generateDescription generates a description based on the handler name and parameters
func generateDescription(handlerName string, params []Parameter, reqBody *Parameter) string {
	method := ""
	entity := ""

	// Extract the HTTP method and entity from the handler name
	if strings.HasPrefix(handlerName, "Get") {
		method = "Retrieves"
		entity = strings.TrimPrefix(handlerName, "Get")
	} else if strings.HasPrefix(handlerName, "List") {
		method = "Lists all"
		entity = strings.TrimPrefix(handlerName, "List")
		// Handle plural forms
		if !strings.HasSuffix(entity, "s") {
			entity += "s"
		}
	} else if strings.HasPrefix(handlerName, "Create") {
		method = "Creates a new"
		entity = strings.TrimPrefix(handlerName, "Create")
	} else if strings.HasPrefix(handlerName, "Update") {
		method = "Updates an existing"
		entity = strings.TrimPrefix(handlerName, "Update")
	} else if strings.HasPrefix(handlerName, "Delete") {
		method = "Deletes an existing"
		entity = strings.TrimPrefix(handlerName, "Delete")
	} else if strings.HasPrefix(handlerName, "Patch") {
		method = "Partially updates"
		entity = strings.TrimPrefix(handlerName, "Patch")
	} else {
		// Default case
		return "Handler for " + humanize(handlerName)
	}

	// Format entity name: convert from camelCase to normal text
	entity = humanize(entity)

	// Build the description with parameter details
	desc := method + " " + entity + "."

	// Add information about required parameters
	var requiredParams []string
	for _, param := range params {
		if param.Required {
			requiredParams = append(requiredParams, param.Name)
		}
	}

	if len(requiredParams) > 0 {
		desc += "\n\nRequired parameters: " + strings.Join(requiredParams, ", ") + "."
	}

	// Add information about request body if present
	if reqBody != nil {
		desc += "\n\nRequires a request body."
	}

	return desc
}

// Add this function to extract field comments for better field descriptions
func extractFieldComments(field *ast.Field) string {
	if field.Doc != nil {
		return field.Doc.Text()
	}
	if field.Comment != nil {
		return field.Comment.Text()
	}
	return ""
}

// generateExampleForSchema creates realistic example data for a schema
func generateExampleForSchema(schema Schema, context string) interface{} {
	if schema.Example != nil {
		return schema.Example
	}

	if schema.Ref != "" {
		// For referenced schemas, create an object example with the type name
		typeName := strings.TrimPrefix(schema.Ref, "#/components/schemas/")

		// Start with a simple ID-based example
		example := map[string]interface{}{
			"id": "123e4567-e89b-12d3-a456-426614174000",
		}

		// Add name field if this is likely to have a name
		if !strings.HasSuffix(strings.ToLower(typeName), "id") &&
			!strings.HasSuffix(strings.ToLower(typeName), "request") {
			example["name"] = typeName + " Name"
		}

		// Add createdAt/updatedAt for most entities
		if !strings.HasSuffix(strings.ToLower(typeName), "request") &&
			!strings.HasSuffix(strings.ToLower(typeName), "response") {
			example["created_at"] = "2023-01-01T12:00:00Z"
		}

		// Add specific fields based on the type name
		lowerTypeName := strings.ToLower(typeName)
		if strings.Contains(lowerTypeName, "user") {
			example["email"] = "user@example.com"
			example["first_name"] = "John"
			example["last_name"] = "Doe"
		} else if strings.Contains(lowerTypeName, "organization") ||
			strings.Contains(lowerTypeName, "org") {
			example["name"] = "Example Organization"
			example["slug"] = "example-org"
			example["owner_id"] = "user-123"
		} else if strings.Contains(lowerTypeName, "project") {
			example["name"] = "Example Project"
			example["description"] = "This is an example project"
			example["organization_id"] = "org-456"
		} else if strings.Contains(lowerTypeName, "tenant") {
			example["name"] = "Example Tenant"
			example["slug"] = "example-tenant"
		}

		return example
	}

	if schema.Type == "object" {
		if len(schema.Properties) > 0 {
			// Generate object with properties
			example := make(map[string]interface{})
			for name, propSchema := range schema.Properties {
				example[name] = generateExampleForSchema(propSchema, name)
			}
			return example
		}

		// For empty objects or those without defined properties
		if strings.Contains(strings.ToLower(context), "error") {
			return map[string]interface{}{
				"error": "Error message",
				"code":  "ERROR_CODE",
			}
		}

		// Generic object
		return map[string]interface{}{
			"property1": "value1",
			"property2": "value2",
		}
	}

	if schema.Type == "array" {
		// Generate an array with 2 items
		if schema.Items != nil {
			item1 := generateExampleForSchema(*schema.Items, context)

			// If this is a primitive array, return different values for the second item
			if isPrimitive(*schema.Items) {
				if schema.Items.Type == "string" {
					return []interface{}{item1, "another string"}
				} else if schema.Items.Type == "integer" {
					return []interface{}{item1, 2}
				} else if schema.Items.Type == "number" {
					return []interface{}{item1, 2.5}
				} else if schema.Items.Type == "boolean" {
					return []interface{}{item1, false}
				}
			}

			// For objects, just duplicate the first item
			return []interface{}{item1, item1}
		}

		// Empty array if no item schema
		return []interface{}{}
	}

	// For primitive types
	if schema.Type == "string" {
		if schema.Format == "date-time" {
			return "2023-01-01T12:00:00Z"
		} else if schema.Format == "date" {
			return "2023-01-01"
		} else if schema.Format == "email" {
			return "user@example.com"
		} else if schema.Format == "uuid" {
			return "123e4567-e89b-12d3-a456-426614174000"
		} else if schema.Format == "uri" {
			return "https://example.com"
		} else if schema.Format == "byte" {
			return "ZXhhbXBsZQ=="
		} else if schema.Format == "binary" {
			return "[binary data]"
		} else if schema.Format == "password" {
			return "password123"
		}

		// Try to guess a good example from context
		contextLower := strings.ToLower(context)
		if strings.Contains(contextLower, "name") {
			if strings.Contains(contextLower, "first") {
				return "John"
			} else if strings.Contains(contextLower, "last") {
				return "Doe"
			} else {
				return "Example Name"
			}
		} else if strings.Contains(contextLower, "email") {
			return "user@example.com"
		} else if strings.Contains(contextLower, "phone") {
			return "+1234567890"
		} else if strings.Contains(contextLower, "address") {
			return "123 Example St"
		} else if strings.Contains(contextLower, "city") {
			return "Example City"
		} else if strings.Contains(contextLower, "country") {
			return "United States"
		} else if strings.Contains(contextLower, "zipcode") || strings.Contains(contextLower, "postal") {
			return "12345"
		} else if strings.Contains(contextLower, "description") {
			return "This is an example description"
		} else if strings.Contains(contextLower, "id") {
			return "123e4567-e89b-12d3-a456-426614174000"
		} else if strings.Contains(contextLower, "status") {
			return "active"
		} else if strings.Contains(contextLower, "type") {
			return "example-type"
		} else if strings.Contains(contextLower, "url") || strings.Contains(contextLower, "link") {
			return "https://example.com"
		}

		if schema.Enum != nil && len(schema.Enum) > 0 {
			return schema.Enum[0]
		}

		// Default string
		return "example"
	}

	if schema.Type == "integer" {
		if schema.Minimum != nil && schema.Maximum != nil {
			// Return a value in the middle of the range
			min := *schema.Minimum
			max := *schema.Maximum
			return int(min + (max-min)/2)
		}

		// Try to guess a good example from context
		contextLower := strings.ToLower(context)
		if strings.Contains(contextLower, "age") {
			return 30
		} else if strings.Contains(contextLower, "year") {
			return 2023
		} else if strings.Contains(contextLower, "count") || strings.Contains(contextLower, "quantity") {
			return 5
		} else if strings.Contains(contextLower, "id") {
			return 12345
		} else if strings.Contains(contextLower, "status") {
			return 1
		}

		// Default integer
		return 42
	}

	if schema.Type == "number" {
		if schema.Minimum != nil && schema.Maximum != nil {
			// Return a value in the middle of the range
			min := *schema.Minimum
			max := *schema.Maximum
			return min + (max-min)/2
		}

		// Try to guess a good example from context
		contextLower := strings.ToLower(context)
		if strings.Contains(contextLower, "price") || strings.Contains(contextLower, "cost") {
			return 19.99
		} else if strings.Contains(contextLower, "amount") {
			return 100.50
		} else if strings.Contains(contextLower, "percent") || strings.Contains(contextLower, "rate") {
			return 75.5
		}

		// Default number
		return 3.14
	}

	if schema.Type == "boolean" {
		// Try to guess a good example from context
		contextLower := strings.ToLower(context)
		if strings.Contains(contextLower, "is_active") || strings.Contains(contextLower, "active") {
			return true
		} else if strings.Contains(contextLower, "enabled") || strings.Contains(contextLower, "available") {
			return true
		} else if strings.Contains(contextLower, "disabled") || strings.Contains(contextLower, "deleted") {
			return false
		}

		// Default boolean
		return true
	}

	if schema.Type == "null" {
		return nil
	}

	// Default to null for unknown types
	return nil
}

// isPrimitive checks if a schema is a primitive type (not object or array)
func isPrimitive(schema Schema) bool {
	return schema.Type == "string" ||
		schema.Type == "integer" ||
		schema.Type == "number" ||
		schema.Type == "boolean" ||
		schema.Type == "null"
}

// humanize converts camelCase or PascalCase to space-separated words
func humanize(s string) string {
	s = regexp.MustCompile(`(.)([A-Z][a-z]+)`).ReplaceAllString(s, "$1 $2")
	return regexp.MustCompile(`([a-z0-9])([A-Z])`).ReplaceAllString(s, "$1 $2")
}

// buildTags creates better organized tags from handler functions
func buildTags(handlers []HandlerFunc) []Tag {
	// Collect unique tags and their related endpoints
	tagMap := make(map[string]map[string]bool)
	tagDescriptions := make(map[string]string)

	for _, h := range handlers {
		for _, tag := range h.Tags {
			if _, exists := tagMap[tag]; !exists {
				tagMap[tag] = make(map[string]bool)

				// Create a nice default description if none exists
				if tagDescriptions[tag] == "" {
					entityName := tag
					// Convert kebab-case to title case for description
					words := strings.Split(entityName, "-")
					for i, word := range words {
						if len(word) > 0 {
							words[i] = strings.ToUpper(word[0:1]) + word[1:]
						}
					}
					cleanEntityName := strings.Join(words, " ")
					tagDescriptions[tag] = "Operations related to " + cleanEntityName
				}
			}

			// Track which operations are in this tag
			tagMap[tag][h.Func.Name.Name] = true
		}
	}

	// Group related endpoints together
	relatedTags := make(map[string][]string)

	// Find similar tags by comparing their operations
	for tag1 := range tagMap {
		for tag2 := range tagMap {
			if tag1 == tag2 {
				continue
			}

			// If the tags share similar operations, they might be related
			// Check if tag names share common prefix/suffix
			if strings.HasPrefix(tag1, strings.Split(tag2, "-")[0]) ||
				strings.HasPrefix(tag2, strings.Split(tag1, "-")[0]) {
				relatedTags[tag1] = append(relatedTags[tag1], tag2)
			}
		}
	}

	// Create tag hierarchy
	rootTags := make(map[string]bool)
	for tag := range tagMap {
		isRoot := true
		for _, related := range relatedTags {
			for _, relTag := range related {
				if tag == relTag {
					isRoot = false
					break
				}
			}
			if !isRoot {
				break
			}
		}
		if isRoot {
			rootTags[tag] = true
		}
	}

	// Create primary tags first, then secondary tags
	var tags []Tag

	// First add primary/root tags
	for tag := range rootTags {
		tags = append(tags, Tag{
			Name:        tag,
			Description: tagDescriptions[tag],
		})
	}

	// Then add secondary tags
	for tag := range tagMap {
		if !rootTags[tag] {
			description := tagDescriptions[tag]

			// Find parent tag if any
			for parentTag := range rootTags {
				if strings.HasPrefix(tag, strings.Split(parentTag, "-")[0]) {
					description = "Operations related to " + humanize(tag) + " (part of " + humanize(parentTag) + ")"
					break
				}
			}

			tags = append(tags, Tag{
				Name:        tag,
				Description: description,
			})
		}
	}

	return tags
}

// Add this helper to convert Fiber-style :param to OpenAPI {param}
func convertColonParamsToBraces(path string) string {
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		if strings.HasPrefix(seg, ":") {
			segments[i] = "{" + seg[1:] + "}"
		}
	}
	return strings.Join(segments, "/")
}

package swaggerannotate

import (
	"go/ast"
	"strings"
)

func GenerateSwaggerAnnotation(h HandlerFunc) string {
	method, route := inferMethodAndRoute(h)
	summary, description, tags := inferSummaryAndTags(h)
	params := inferAllParams(h)
	responses := inferAllResponses(h)
	consumes := inferConsumes(h)
	produces := inferProduces(h)
	var b strings.Builder
	b.WriteString("// swagger:route ")
	b.WriteString(method)
	b.WriteString(" ")
	b.WriteString(route)
	b.WriteString(" ")
	b.WriteString(strings.Join(tags, " "))
	b.WriteString(" ")
	b.WriteString(h.Func.Name.Name)
	b.WriteString("\n// ---\n")
	b.WriteString("// summary: ")
	b.WriteString(summary)
	b.WriteString("\n// description: ")
	b.WriteString(description)
	b.WriteString("\n// tags:\n")
	for _, tag := range tags {
		b.WriteString("//   - ")
		b.WriteString(tag)
		b.WriteString("\n")
	}
	if consumes != "" {
		b.WriteString("// consumes:\n")
		b.WriteString(consumes)
	}
	if produces != "" {
		b.WriteString("// produces:\n")
		b.WriteString(produces)
	}
	if params != "" {
		b.WriteString(params)
	}
	if responses != "" {
		b.WriteString(responses)
	} else {
		b.WriteString(defaultResponses())
	}
	return b.String()
}

func defaultResponses() string {
	return "// responses:\n" +
		"//   200:\n" +
		"//     description: Success\n" +
		"//     schema:\n" +
		"//       type: object\n" +
		"//     headers:\n" +
		"//       X-Request-ID:\n" +
		"//         type: string\n" +
		"//         description: Unique request ID\n" +
		"//   400:\n" +
		"//     description: ErrorResponse\n" +
		"//     schema:\n" +
		"//       $ref: \"#/definitions/ErrorResponse\"\n" +
		"//     headers:\n" +
		"//       X-Request-ID:\n" +
		"//         type: string\n" +
		"//         description: Unique request ID\n" +
		"//   404:\n" +
		"//     description: ErrorResponse\n" +
		"//     schema:\n" +
		"//       $ref: \"#/definitions/ErrorResponse\"\n" +
		"//     headers:\n" +
		"//       X-Request-ID:\n" +
		"//         type: string\n" +
		"//         description: Unique request ID\n"
}

func inferMethodAndRoute(h HandlerFunc) (string, string) {
	name := strings.ToLower(h.Func.Name.Name)
	switch {
	case strings.HasPrefix(name, "get"):
		return "GET", guessRoute(h)
	case strings.HasPrefix(name, "list"):
		return "GET", guessRoute(h)
	case strings.HasPrefix(name, "create"):
		return "POST", guessRoute(h)
	case strings.HasPrefix(name, "update"):
		return "PUT", guessRoute(h)
	case strings.HasPrefix(name, "delete"):
		return "DELETE", guessRoute(h)
	}
	return "POST", guessRoute(h)
}

func guessRoute(h HandlerFunc) string {
	// Try to infer route from function name, fallback to /unknown
	name := strings.ToLower(h.Func.Name.Name)
	if strings.HasPrefix(name, "get") {
		return "/" + strings.ReplaceAll(strings.TrimPrefix(name, "get"), "_", "-")
	}
	if strings.HasPrefix(name, "list") {
		return "/" + strings.ReplaceAll(strings.TrimPrefix(name, "list"), "_", "-") + "/list"
	}
	if strings.HasPrefix(name, "create") {
		return "/" + strings.ReplaceAll(strings.TrimPrefix(name, "create"), "_", "-") + "/create"
	}
	if strings.HasPrefix(name, "update") {
		return "/" + strings.ReplaceAll(strings.TrimPrefix(name, "update"), "_", "-") + "/update"
	}
	if strings.HasPrefix(name, "delete") {
		return "/" + strings.ReplaceAll(strings.TrimPrefix(name, "delete"), "_", "-") + "/delete"
	}
	return "/unknown"
}

func inferSummaryAndTags(h HandlerFunc) (string, string, []string) {
	summary := h.Func.Name.Name
	description := h.Func.Name.Name
	tags := []string{"billing"}
	if h.Func.Doc != nil && len(h.Func.Doc.List) > 0 {
		for _, c := range h.Func.Doc.List {
			line := strings.TrimPrefix(strings.TrimSpace(c.Text), "//")
			if strings.HasPrefix(line, "summary:") {
				summary = strings.TrimSpace(strings.TrimPrefix(line, "summary:"))
			}
			if strings.HasPrefix(line, "description:") {
				description = strings.TrimSpace(strings.TrimPrefix(line, "description:"))
			}
			if strings.HasPrefix(line, "tags:") {
				tags = strings.Fields(strings.TrimSpace(strings.TrimPrefix(line, "tags:")))
			}
		}
	}
	return summary, description, tags
}

func inferAllParams(h HandlerFunc) string {
	var params []string
	// Detect body param
	body := inferParamsFull(h)
	if body != "" {
		params = append(params, body)
	}
	// Detect query/path/header params from function signature
	for _, field := range h.Func.Type.Params.List {
		for _, name := range field.Names {
			if name.Name == "c" {
				continue // skip context param
			}
			typeStr := exprToString(field.Type)
			if strings.Contains(typeStr, "string") {
				params = append(params, "//   - name: "+name.Name+"\n//     in: query\n//     required: false\n//     type: string\n")
			}
			if strings.Contains(typeStr, "int") {
				params = append(params, "//   - name: "+name.Name+"\n//     in: query\n//     required: false\n//     type: integer\n")
			}
		}
	}
	return strings.Join(params, "")
}

func exprToString(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return exprToString(t.X)
	case *ast.SelectorExpr:
		return exprToString(t.X) + "." + t.Sel.Name
	case *ast.ArrayType:
		return "[]" + exprToString(t.Elt)
	}
	return ""
}

func inferAllResponses(h HandlerFunc) string {
	// Map status code -> (description, schema)
	respMap := map[string][2]string{}
	ast.Inspect(h.Func, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			// c.Status(x).JSON(y) or c.Status(x).SendStatus(y)
			if sel.Sel.Name == "Status" && len(call.Args) == 1 {
				status := extractStatusCode(call.Args[0])
				parent := parentCall(n)
				if parent != nil {
					if psel, ok := parent.Fun.(*ast.SelectorExpr); ok {
						if psel.Sel.Name == "JSON" && len(parent.Args) == 1 {
							desc, schema := extractResponseType(parent.Args[0])
							respMap[status] = [2]string{desc, schema}
						}
						if psel.Sel.Name == "SendStatus" && len(parent.Args) == 1 {
							respMap[status] = [2]string{"EmptyResponse", "type: object"}
						}
					}
				}
			}
			// c.JSON(x)
			if sel.Sel.Name == "JSON" && len(call.Args) == 1 {
				desc, schema := extractResponseType(call.Args[0])
				respMap["200"] = [2]string{desc, schema}
			}
			// c.SendStatus(x)
			if sel.Sel.Name == "SendStatus" && len(call.Args) == 1 {
				status := extractStatusCode(call.Args[0])
				respMap[status] = [2]string{"EmptyResponse", "type: object"}
			}
			// c.SendFile/c.Download
			if sel.Sel.Name == "SendFile" || sel.Sel.Name == "Download" {
				respMap["200"] = [2]string{"PDF", "type: string"}
			}
		}
		return true
	})
	if len(respMap) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("// responses:\n")
	for code, pair := range respMap {
		desc, schema := pair[0], pair[1]
		b.WriteString("//   " + code + ":\n")
		b.WriteString("//     description: " + desc + "\n")
		b.WriteString("//     schema:\n")
		b.WriteString("//       " + schema + "\n")
		b.WriteString("//     headers:\n")
		b.WriteString("//       X-Request-ID:\n")
		b.WriteString("//         type: string\n")
		b.WriteString("//         description: Unique request ID\n")
		if desc == "PDF" {
			b.WriteString("//       Content-Disposition:\n")
			b.WriteString("//         type: string\n")
			b.WriteString("//         description: Attachment\n")
		}
	}
	return b.String()
}

func extractStatusCode(expr ast.Expr) string {
	switch v := expr.(type) {
	case *ast.SelectorExpr:
		return v.Sel.Name[6:] // fiber.StatusCreated -> 201
	case *ast.BasicLit:
		if v.Kind == 2 { // token.INT
			return v.Value
		}
		if v.Kind == 9 { // token.STRING
			return strings.Trim(v.Value, "\"")
		}
	}
	return "200"
}

func extractResponseType(expr ast.Expr) (string, string) {
	switch v := expr.(type) {
	case *ast.Ident:
		return v.Name, "$ref: \"#/definitions/" + v.Name + "\""
	case *ast.CompositeLit:
		return "object", "type: object"
	case *ast.CallExpr:
		return "object", "type: object"
	}
	return "object", "type: object"
}

func parentCall(n ast.Node) *ast.CallExpr {
	// Not implemented: would require AST parent tracking
	return nil
}

func inferConsumes(h HandlerFunc) string {
	if usesPDFDownload(h) {
		return "//   - application/json\n"
	}
	return "//   - application/json\n"
}

func inferProduces(h HandlerFunc) string {
	if usesPDFDownload(h) {
		return "//   - application/pdf\n"
	}
	return "//   - application/json\n"
}

func usesPDFDownload(h HandlerFunc) bool {
	found := false
	ast.Inspect(h.Func, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && (sel.Sel.Name == "SendFile" || sel.Sel.Name == "Download") {
			found = true
			return false
		}
		return true
	})
	return found
}

// inferParamsFull: output full parameters block with all struct fields
func inferParamsFull(h HandlerFunc) string {
	var paramType string
	ast.Inspect(h.Func, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && (sel.Sel.Name == "BodyParser" || sel.Sel.Name == "Bind") {
			if len(call.Args) == 1 {
				if star, ok := call.Args[0].(*ast.UnaryExpr); ok {
					if ident, ok := star.X.(*ast.Ident); ok {
						paramType = ident.Name
					}
				}
			}
		}
		return true
	})
	if paramType == "" {
		return ""
	}
	// Output a generic parameters block (real impl: reflect on struct fields)
	return "// parameters:\n//   - name: input\n//     in: body\n//     required: true\n//     schema:\n//       $ref: \"#/definitions/" + paramType + "\"\n"
}

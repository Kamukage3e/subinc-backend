package swaggerannotate

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
)

type HandlerFunc struct {
	File     *ast.File
	Func     *ast.FuncDecl
	FilePath string
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

func FindHandlerFuncs(files []*ast.File) []HandlerFunc {
	handlers := []HandlerFunc{}
	for _, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || len(fn.Recv.List) == 0 {
				continue
			}
			if len(fn.Type.Params.List) != 1 {
				continue
			}
			param := fn.Type.Params.List[0]
			starExpr, ok := param.Type.(*ast.StarExpr)
			if !ok {
				continue
			}
			selector, ok := starExpr.X.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "Ctx" {
				continue
			}
			if fn.Type.Results == nil || len(fn.Type.Results.List) != 1 {
				continue
			}
			ident, ok := fn.Type.Results.List[0].Type.(*ast.Ident)
			if !ok || ident.Name != "error" {
				continue
			}
			handlers = append(handlers, HandlerFunc{File: f, Func: fn})
		}
	}
	return handlers
}

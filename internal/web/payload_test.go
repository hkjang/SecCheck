package web

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
)

// Request payloads are decoded with DisallowUnknownFields. encoding/json
// matches an untagged field only by its Go name, case-insensitively, so a
// multi-word field such as DisplayName never matches the display_name key the
// UI sends — and because unknown fields are rejected, the whole request fails
// with a confusing 400. That silently broke profile saving from the first
// release until an integration test happened to exercise it. This test makes
// the mistake impossible to reintroduce.
func TestDecodedPayloadFieldsCarryJSONTags(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var problems []string
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			for variable, structType := range localStructs(fn) {
				if !isDecoded(fn, variable) {
					continue
				}
				for _, field := range untaggedMultiWordFields(structType) {
					problems = append(problems, fset.Position(structType.Pos()).String()+" "+fn.Name.Name+"."+variable+"."+field)
				}
			}
		}
	}
	for _, problem := range problems {
		t.Errorf("decoded payload field has no json tag, so the snake_case key is rejected: %s", problem)
	}
}

// localStructs maps each `var name struct{...}` in the function to its type.
func localStructs(fn *ast.FuncDecl) map[string]*ast.StructType {
	out := map[string]*ast.StructType{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		decl, ok := n.(*ast.DeclStmt)
		if !ok {
			return true
		}
		gen, ok := decl.Decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			return true
		}
		for _, spec := range gen.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			structType, ok := value.Type.(*ast.StructType)
			if !ok {
				continue
			}
			for _, ident := range value.Names {
				out[ident.Name] = structType
			}
		}
		return true
	})
	return out
}

// isDecoded reports whether the variable is passed to one of the JSON body
// decoders, which are the calls that enable DisallowUnknownFields.
func isDecoded(fn *ast.FuncDecl, variable string) bool {
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		ident, ok := call.Fun.(*ast.Ident)
		if !ok || (ident.Name != "decodeJSON" && ident.Name != "decodeOptionalJSON") {
			return true
		}
		for _, arg := range call.Args {
			unary, ok := arg.(*ast.UnaryExpr)
			if !ok || unary.Op != token.AND {
				continue
			}
			if target, ok := unary.X.(*ast.Ident); ok && target.Name == variable {
				found = true
			}
		}
		return true
	})
	return found
}

// untaggedMultiWordFields returns exported fields whose Go name has more than
// one word and no json tag. Single-word names still match case-insensitively,
// so they are safe.
func untaggedMultiWordFields(structType *ast.StructType) []string {
	var out []string
	for _, field := range structType.Fields.List {
		if field.Tag != nil && strings.Contains(field.Tag.Value, "json:") {
			continue
		}
		for _, name := range field.Names {
			if name.IsExported() && countWords(name.Name) > 1 {
				out = append(out, name.Name)
			}
		}
	}
	return out
}

func countWords(name string) int {
	words := 0
	for i, r := range name {
		if i == 0 || unicode.IsUpper(r) {
			words++
		}
	}
	return words
}

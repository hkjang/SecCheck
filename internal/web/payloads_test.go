package web

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// The OpenAPI document describes request bodies from a table, and a table is
// exactly the sort of thing that stops matching the code. This rebuilds it
// from the handlers and insists the two agree, in both directions.
func TestRequestPayloadsMatchTheHandlers(t *testing.T) {
	derived := derivePayloads(t)
	for key, want := range derived {
		got, ok := requestPayloads[key]
		if !ok {
			t.Errorf("%s decodes a body that the OpenAPI document never describes", key)
			continue
		}
		if len(got) != len(want) {
			t.Errorf("%s: document lists %d properties, the handler decodes %d", key, len(got), len(want))
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%s property %d: document has %v, the handler decodes %v", key, i, got[i], want[i])
			}
		}
	}
	for key := range requestPayloads {
		if _, ok := derived[key]; !ok {
			t.Errorf("the OpenAPI document describes a body for %s, which decodes none", key)
		}
	}
	if len(derived) < 30 {
		t.Fatalf("only %d payloads derived; the AST walk must have stopped working", len(derived))
	}
}

func derivePayloads(t *testing.T) map[string][]payloadField {
	t.Helper()
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	named := map[string]*ast.StructType{}
	decls := map[string]*ast.FuncDecl{}
	serverSrc := ""
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if filepath.Base(path) == "server.go" {
			serverSrc = string(body)
		}
		f, err := parser.ParseFile(fset, path, body, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			if gen, ok := decl.(*ast.GenDecl); ok {
				for _, spec := range gen.Specs {
					if ts, ok := spec.(*ast.TypeSpec); ok {
						if st, ok := ts.Type.(*ast.StructType); ok {
							named[ts.Name.Name] = st
						}
					}
				}
			}
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv != nil && fn.Body != nil {
				decls[fn.Name.Name] = fn
			}
		}
	}
	handlers := map[string][]payloadField{}
	for name, fn := range decls {
		if fs := payloadFields(fn, named, decls, 0); fs != nil {
			handlers[name] = fs
		}
	}
	out := map[string][]payloadField{}
	route := regexp.MustCompile(`s\.handle\("(\w+)",\s*"([^"]+)",[\s\S]*?s\.(\w+)\)`)
	for _, m := range route.FindAllStringSubmatch(serverSrc, -1) {
		if fs, ok := handlers[m[3]]; ok {
			out[m[1]+" "+m[2]] = fs
		}
	}
	return out
}

// payloadFields returns the JSON fields of the `var in struct{...}` a handler
// decodes, or nil when it decodes nothing.
func payloadFields(fn *ast.FuncDecl, named map[string]*ast.StructType, decls map[string]*ast.FuncDecl, depth int) []payloadField {
	decodes := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok && (id.Name == "decodeJSON" || id.Name == "decodeOptionalJSON") {
			decodes = true
		}
		return true
	})
	if !decodes {
		// approveReview and rejectReview only pass a decision through to a
		// shared handler, so the payload lives one call away.
		if depth > 0 {
			return nil
		}
		var out []payloadField
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if target, ok := decls[sel.Sel.Name]; ok && out == nil {
				out = payloadFields(target, named, decls, depth+1)
			}
			return true
		})
		return out
	}
	var out []payloadField
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok || len(spec.Names) != 1 || spec.Names[0].Name != "in" {
			return true
		}
		st, ok := spec.Type.(*ast.StructType)
		if !ok {
			if id, isIdent := spec.Type.(*ast.Ident); isIdent {
				st, ok = named[id.Name]
			}
			if !ok {
				return true
			}
		}
		for _, f := range st.Fields.List {
			name := ""
			if f.Tag != nil {
				name = strings.Split(reflect.StructTag(strings.Trim(f.Tag.Value, "`")).Get("json"), ",")[0]
			}
			for _, id := range f.Names {
				n := name
				if n == "" {
					// Untagged: encoding/json matches case-insensitively, so
					// the lower-camel form is what callers actually send.
					n = strings.ToLower(id.Name[:1]) + id.Name[1:]
				}
				if n == "-" {
					continue
				}
				out = append(out, payloadField{n, typeName(f.Type)})
			}
		}
		return true
	})
	return out
}

func typeName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return typeName(t.X)
	case *ast.ArrayType:
		return "[]" + typeName(t.Elt)
	case *ast.SelectorExpr:
		return typeName(t.X) + "." + t.Sel.Name
	case *ast.MapType:
		return "map"
	case *ast.InterfaceType:
		return "any"
	}
	return "any"
}

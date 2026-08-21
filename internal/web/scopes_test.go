package web

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The OpenAPI document tells integrators which calls are gated on being a
// participant rather than on a role. That claim is only useful while it
// matches the handlers, so it is rebuilt from them here.
func TestObjectScopedRoutesMatchTheHandlers(t *testing.T) {
	derived := deriveObjectScoped(t)
	// The MCP endpoint reaches scoped handlers through its tools, but the
	// flag would describe the JSON-RPC transport rather than the call.
	delete(derived, "POST /mcp")
	for key := range derived {
		if !objectScopedRoutes[key] {
			t.Errorf("%s authorises per review but the document does not say so", key)
		}
	}
	for key := range objectScopedRoutes {
		if !derived[key] {
			t.Errorf("the document says %s authorises per review; no handler check does", key)
		}
	}
	if len(derived) < 15 {
		t.Fatalf("only %d scoped routes derived; the AST walk must have stopped working", len(derived))
	}
}

func deriveObjectScoped(t *testing.T) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
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
		for _, d := range f.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv != nil && fn.Body != nil {
				decls[fn.Name.Name] = fn
			}
		}
	}
	guard := regexp.MustCompile(`^can(Access|Edit|Review|AccessReviewAs)`)
	var scoped func(fn *ast.FuncDecl, depth int) bool
	scoped = func(fn *ast.FuncDecl, depth int) bool {
		found := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if guard.MatchString(sel.Sel.Name) {
				found = true
			}
			if depth < 2 && !found {
				if target, ok := decls[sel.Sel.Name]; ok {
					found = scoped(target, depth+1)
				}
			}
			return true
		})
		return found
	}
	out := map[string]bool{}
	route := regexp.MustCompile(`s\.handle\("(\w+)",\s*"([^"]+)",[\s\S]*?s\.(\w+)\)`)
	for _, m := range route.FindAllStringSubmatch(serverSrc, -1) {
		if fn, ok := decls[m[3]]; ok && scoped(fn, 0) {
			out[m[1]+" "+m[2]] = true
		}
	}
	return out
}

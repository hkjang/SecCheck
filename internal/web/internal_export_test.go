package web

// ObjectScopedRoutes lets the HTTP-level tests, which live in the external
// test package, walk the same list the OpenAPI document is built from. Test
// only: this file is not part of the built binary.
var ObjectScopedRoutes = objectScopedRoutes

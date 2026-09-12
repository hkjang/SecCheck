package store

import "testing"

// The scratch schema name goes into CREATE SCHEMA unquoted, so it has to be a
// bare identifier. NewID returns a UUID whose ninth character is always a
// hyphen; taking a prefix of it produced a name Postgres refused every time,
// and the database tests skip without a DSN, so nothing said so.
func TestTheScratchSchemaNameIsABareIdentifier(t *testing.T) {
	for i := 0; i < 200; i++ {
		name := scratchSchemaName()
		for _, r := range name {
			isLower := r >= 'a' && r <= 'z'
			isDigit := r >= '0' && r <= '9'
			if !isLower && !isDigit && r != '_' {
				t.Fatalf("%q holds %q, which CREATE SCHEMA cannot take unquoted", name, r)
			}
		}
	}
}

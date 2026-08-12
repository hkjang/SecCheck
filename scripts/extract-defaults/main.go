package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/hkjang/SecCheck/internal/store"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go run ./scripts/extract-defaults <source.xlsx> <output.json>")
		os.Exit(2)
	}
	checklists, err := store.ExtractWorkbookDefaults(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	encoded, err := json.MarshalIndent(checklists, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	encoded = append(encoded, '\n')
	if err = os.WriteFile(os.Args[2], encoded, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

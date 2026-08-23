//go:build !linux

package vault

import "errors"

// The service ships in a Linux container; elsewhere the figure is simply not
// reported rather than guessed.
func diskSpace(string) (uint64, uint64, error) {
	return 0, 0, errors.New("disk space is only reported on linux")
}

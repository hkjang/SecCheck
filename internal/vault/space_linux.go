//go:build linux

package vault

import "syscall"

// diskSpace reports what is left on the filesystem holding the evidence
// volume. Available is what a non-root process may actually use, which is the
// number that decides whether the next upload succeeds.
func diskSpace(path string) (free, total uint64, err error) {
	var fs syscall.Statfs_t
	if err = syscall.Statfs(path, &fs); err != nil {
		return 0, 0, err
	}
	return fs.Bavail * uint64(fs.Bsize), fs.Blocks * uint64(fs.Bsize), nil
}

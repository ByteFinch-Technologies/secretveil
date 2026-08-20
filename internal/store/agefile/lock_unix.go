//go:build unix

package agefile

import (
	"os"
	"syscall"
)

// lockDir takes the exclusive advisory lock of a directory and returns the
// function that releases it. The call waits for any other holder.
//
// The lock sits on the directory and not on the store file, because every
// write replaces the store file by a rename. A lock on the file would hold the
// old inode after the first write, and the next writer would take the lock of
// a file that nothing reads any more.
func lockDir(dir string) (func(), error) {
	d, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(d.Fd()), syscall.LOCK_EX); err != nil {
		d.Close()
		return nil, err
	}
	return func() {
		// The close releases the lock by itself. The explicit unlock says so
		// to a reader, and it costs nothing.
		_ = syscall.Flock(int(d.Fd()), syscall.LOCK_UN)
		d.Close()
	}, nil
}

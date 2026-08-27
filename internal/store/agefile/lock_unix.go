//go:build unix

package agefile

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

// quietWait is the time that lockDir waits in silence before it tells the user
// why the command does not return. A store that another command holds for a
// few milliseconds needs no message. A store that a long command holds does.
const quietWait = 300 * time.Millisecond

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
	fd := int(d.Fd())

	// Ask for the lock without a wait first. The free store is the normal
	// case, and it must cost nothing.
	err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		err = waitForLock(fd)
	}
	if err != nil {
		d.Close()
		return nil, err
	}
	return func() {
		// The close releases the lock by itself. The explicit unlock says so
		// to a reader, and it costs nothing.
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		d.Close()
	}, nil
}

// waitForLock waits for the lock of an open directory. It tries again in
// silence for quietWait, and then it prints one line and blocks.
//
// Without the line a blocked write looks frozen. The user sees no output, and
// the command appears to hang.
func waitForLock(fd int) error {
	deadline := time.Now().Add(quietWait)
	for time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
		err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			return err
		}
	}
	fmt.Fprintln(os.Stderr, "secretveil: another secretveil command holds the store. this command waits for it.")
	return syscall.Flock(fd, syscall.LOCK_EX)
}

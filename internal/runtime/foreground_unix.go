//go:build unix

package runtime

import (
	"os"

	"golang.org/x/sys/unix"
)

// inForeground reports whether the process group of secretveil is the
// foreground group of its controlling terminal. Only the foreground group gets
// the signal of a key such as Ctrl-C. The check runs when the signal arrives,
// because a shell can move a job between the foreground and the background.
func inForeground() bool {
	tty, err := os.Open("/dev/tty")
	if err != nil {
		// No controlling terminal, so no key press sent the signal.
		return false
	}
	defer func() { _ = tty.Close() }()
	fg, err := unix.IoctlGetInt(int(tty.Fd()), unix.TIOCGPGRP)
	if err != nil {
		return false
	}
	return fg == unix.Getpgrp()
}

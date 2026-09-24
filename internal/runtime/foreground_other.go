//go:build !unix

package runtime

// inForeground reports false on a system with no process groups, so every
// signal is passed on to the child.
func inForeground() bool { return false }

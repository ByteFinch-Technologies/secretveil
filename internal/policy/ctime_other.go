//go:build unix && !(darwin || freebsd || netbsd || linux)

package policy

import "syscall"

// ctime returns 0. The releases are for macOS and Linux only, and this file
// keeps a build from source on another Unix working. The stamp then holds the
// modification time and the inode only.
func ctime(*syscall.Stat_t) int64 { return 0 }

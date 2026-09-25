//go:build darwin || freebsd || netbsd

package policy

import "syscall"

// ctime returns the change time of the inode, in nanoseconds.
func ctime(st *syscall.Stat_t) int64 { return st.Ctimespec.Nano() }

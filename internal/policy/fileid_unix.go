//go:build unix

package policy

import (
	"fmt"
	"os"
	"syscall"
)

// fileID names one copy of a file on disk: its modification time, its inode
// and its change time. A file that is removed and written again gets a new
// inode and a new time, even when the bytes are the same.
//
// A rename and a hard link keep the inode and the modification time, so
// "mv policy.toml off" and back gives the same inode. They change the change
// time, and a program cannot set the change time back, so the stamp changes.
func fileID(info os.FileInfo) string {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf("%d.%d.%d", info.ModTime().UnixNano(), st.Ino, ctime(st))
	}
	return fmt.Sprintf("%d", info.ModTime().UnixNano())
}

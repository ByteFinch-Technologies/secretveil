//go:build unix

package policy

import (
	"fmt"
	"os"
	"syscall"
)

// fileID names one copy of a file on disk: its modification time and its
// inode. A file that is removed and written again gets a new inode and a new
// time, even when the bytes are the same.
func fileID(info os.FileInfo) string {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf("%d.%d", info.ModTime().UnixNano(), st.Ino)
	}
	return fmt.Sprintf("%d", info.ModTime().UnixNano())
}

//go:build !unix

package policy

import (
	"fmt"
	"os"
)

// fileID names one copy of a file on disk by its modification time. This
// system gives no inode through os.FileInfo.
func fileID(info os.FileInfo) string {
	return fmt.Sprintf("%d", info.ModTime().UnixNano())
}

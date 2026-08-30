//go:build unix

package runtime

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestUnreadInRootDoesNotOpenANamedPipe holds the one failure that would stop
// the command from starting. A read of a named pipe waits until somebody
// writes to it, and run must never wait.
func TestUnreadInRootDoesNotOpenANamedPipe(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".env", "API_KEY=sv://api_key\n")
	if err := syscall.Mkfifo(filepath.Join(dir, ".env.pipe"), 0o600); err != nil {
		t.Skipf("this machine does not make a named pipe: %v", err)
	}

	done := make(chan []string, 1)
	go func() { done <- UnreadInRoot(dir, []string{".env"}) }()

	select {
	case got := <-done:
		if len(got) != 0 {
			t.Errorf("want no name, got %v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("UnreadInRoot opened the named pipe and waited")
	}
}

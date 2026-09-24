//go:build unix

package runtime

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
)

// signalHelper is set in the environment of the helper run.
const signalHelper = "SECRETVEIL_TEST_SIGNAL_HELPER"

// countINT counts the SIGINT signals the child gets, and reports the total.
// It is perl and not sh, because sh can run its trap once for two signals
// that arrive close together, and then the count hides the fault.
const countINT = `$n = 0;
$SIG{INT} = sub { $n++ };
$| = 1;
print "ready\n";
select(undef, undef, undef, 0.1) for 1 .. 20;
print "total INT=$n\n";`

// TestOneCtrlCIsOneSignal guards the signal forward in pipe mode. The child is
// in the process group of secretveil, so a Ctrl-C at the terminal reaches it
// directly. A second copy from secretveil made one key press into two
// signals, and a tool such as Terraform reads a second Ctrl-C as "stop now".
//
// The test runs this test binary again on a pseudo terminal, where it is the
// foreground process group, and types one Ctrl-C.
func TestOneCtrlCIsOneSignal(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestSignalHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), signalHelper+"=1")
	ptmx, err := pty.Start(cmd)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ptmx.Close() }()

	var mu sync.Mutex
	var out bytes.Buffer
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := ptmx.Read(buf)
			mu.Lock()
			out.Write(buf[:n])
			mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	wait := func(text string) string {
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			got := out.String()
			mu.Unlock()
			if strings.Contains(got, text) {
				return got
			}
			time.Sleep(20 * time.Millisecond)
		}
		mu.Lock()
		defer mu.Unlock()
		t.Fatalf("no %q in the output: %q", text, out.String())
		return ""
	}

	wait("ready")
	if _, err := ptmx.Write([]byte{0x03}); err != nil {
		t.Fatal(err)
	}
	got := wait("total INT=")
	_ = cmd.Wait()
	if !strings.Contains(got, "total INT=1") {
		t.Fatalf("one Ctrl-C did not give exactly one SIGINT: %q", got)
	}
}

// TestAKillStillReachesTheChild guards the other half of the rule. When no key
// press sent the signal, secretveil is the only way it reaches the child. A
// script that stops a run with kill -INT must still stop the child.
func TestAKillStillReachesTheChild(t *testing.T) {
	if inForeground() {
		t.Skip("this test process is in the foreground of a terminal")
	}
	// The test process holds SIGINT too, so the signal cannot stop the test
	// binary if it arrives before the runtime is ready for it.
	hold := make(chan os.Signal, 1)
	signal.Notify(hold, syscall.SIGINT)
	defer signal.Stop(hold)

	out := newSafeBuffer()
	done := make(chan error, 1)
	go func() {
		_, err := Run(context.Background(), Config{
			Args:   []string{"perl", "-e", countINT},
			Env:    os.Environ(),
			Stdin:  strings.NewReader(""),
			Stdout: out,
			Stderr: newSafeBuffer(),
			NoPTY:  true,
		})
		done <- err
	}()
	deadline := time.Now().Add(15 * time.Second)
	for !strings.Contains(out.String(), "ready") {
		if time.Now().After(deadline) {
			t.Fatalf("the child did not start: %q", out.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the run did not end")
	}
	if !strings.Contains(out.String(), "total INT=1") {
		t.Fatalf("the kill did not reach the child once: %q", out.String())
	}
}

// TestSignalHelper is the program that TestOneCtrlCIsOneSignal starts on a
// pseudo terminal. It does nothing in a normal test run.
func TestSignalHelper(t *testing.T) {
	if os.Getenv(signalHelper) != "1" {
		t.Skip("this runs only as the helper of TestOneCtrlCIsOneSignal")
	}
	_, err := Run(context.Background(), Config{
		Args:   []string{"perl", "-e", countINT},
		Env:    os.Environ(),
		Stdin:  strings.NewReader(""),
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		NoPTY:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
}

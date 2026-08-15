package runtime

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/ByteFinch-Technologies/secretveil/internal/redact"
	"github.com/creack/pty"
	"golang.org/x/term"
)

// DefaultIdleFlush is how long the filter waits before it releases the bytes
// it holds back.
//
// The filter must hold a few bytes, because the next byte can complete a
// secret. A program that prints "Password: " and then waits would therefore
// show nothing. The timer solves this. The value is short enough that a person
// does not see the delay, and long enough that it does not fire on every byte
// of a fast stream.
const DefaultIdleFlush = 40 * time.Millisecond

// ErrNoCommand is returned when the caller gives no program to start.
var ErrNoCommand = errors.New("no command to run")

// Config describes one child process.
type Config struct {
	// Args is the program and its arguments.
	Args []string
	// Dir is the working directory of the child. An empty value keeps the
	// working directory of the parent.
	Dir string
	// Env is the child environment. A nil value means os.Environ.
	Env []string
	// Values maps each reference to the secret behind it. The filter removes
	// every one of these values from the child output.
	Values map[string]string
	// Stdin, Stdout and Stderr default to the streams of the parent.
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	// NoPTY starts the child on plain pipes, even when the output is a
	// terminal. Use it when the two output streams must stay apart.
	NoPTY bool
	// ForcePTY starts the child on a pseudo terminal, even when the output is
	// not a terminal. Use it when a tool prints colour only for a terminal and
	// the colour must reach the log. NoPTY wins over ForcePTY.
	ForcePTY bool
	// IdleFlush is the quiet time before a flush. Zero means DefaultIdleFlush.
	IdleFlush time.Duration
	// MinLen is the shortest value the filter removes. Zero means the default.
	MinLen int
}

// Result reports what happened.
type Result struct {
	// ExitCode is the exit code of the child. A child that a signal stopped
	// reports 128 plus the signal number, which is what a shell reports.
	ExitCode int
	// Hits counts, for each reference, how many times the filter removed the
	// value from the output.
	Hits map[string]int
	// Skipped names each value that was too short to remove safely.
	Skipped []string
	// PTY is true when the child ran on a pseudo terminal.
	PTY bool
}

// Run starts the child and waits for it.
//
// The error is about starting or supervising the child. A child that runs and
// then fails is not an error here. Read ExitCode for that.
func Run(ctx context.Context, cfg Config) (*Result, error) {
	if len(cfg.Args) == 0 {
		return nil, ErrNoCommand
	}
	stdin := cfg.Stdin
	if stdin == nil {
		stdin = os.Stdin
	}
	stdout := cfg.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	stderr := cfg.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	idle := cfg.IdleFlush
	if idle <= 0 {
		idle = DefaultIdleFlush
	}

	built := redact.Build(cfg.Values, redact.Options{MinLen: cfg.MinLen})
	res := &Result{Skipped: built.Skipped}

	cmd := exec.Command(cfg.Args[0], cfg.Args[1:]...)
	cmd.Dir = cfg.Dir
	cmd.Env = cfg.Env
	if cmd.Env == nil {
		cmd.Env = os.Environ()
	}

	if cfg.NoPTY || (!cfg.ForcePTY && !isTerminal(stdout)) {
		return runPipes(ctx, cmd, res, built.Matcher, idle, stdin, stdout, stderr)
	}
	return runPTY(ctx, cmd, res, built.Matcher, idle, stdin, stdout)
}

// runPipes starts the child with a pipe on each stream. This is the path for a
// build server and for an AI tool that captures the output.
func runPipes(ctx context.Context, cmd *exec.Cmd, res *Result, m *redact.Matcher,
	idle time.Duration, stdin io.Reader, stdout, stderr io.Writer) (*Result, error) {

	wOut := redact.NewWriter(stdout, m)
	wErr := redact.NewWriter(stderr, m)
	cmd.Stdin = stdin
	cmd.Stdout = wOut
	cmd.Stderr = wErr

	if err := cmd.Start(); err != nil {
		return nil, err
	}
	stopSignals := forwardSignals(cmd)
	stopTimer := startIdleFlush(idle, wOut, wErr)

	err := cmd.Wait()
	stopTimer()
	stopSignals()

	// Close in stream order, so a message that the child sent last still
	// arrives last.
	closeErr := wOut.Close()
	if e := wErr.Close(); closeErr == nil {
		closeErr = e
	}

	res.ExitCode = exitCode(cmd, err)
	res.Hits = mergeHits(wOut.Hits(), wErr.Hits())
	if isStartFailure(err) {
		return res, err
	}
	if ctx.Err() != nil {
		return res, ctx.Err()
	}
	return res, closeErr
}

// runPTY starts the child on a pseudo terminal. This is the path for a person
// at a keyboard. A pseudo terminal keeps colour, progress bars and a password
// prompt working, because the child still believes it talks to a terminal.
func runPTY(ctx context.Context, cmd *exec.Cmd, res *Result, m *redact.Matcher,
	idle time.Duration, stdin io.Reader, stdout io.Writer) (*Result, error) {

	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, err
	}
	res.PTY = true
	defer func() { _ = ptmx.Close() }()

	stopResize := followResize(ptmx, stdout)
	defer stopResize()

	// Raw mode gives every key press straight to the child. The restore runs
	// on a panic as well, because a terminal left in raw mode is unusable and
	// the user must then type reset without seeing what they type.
	if restore, ok := makeRaw(stdin); ok {
		defer restore()
	}

	w := redact.NewWriter(stdout, m)
	stopSignals := forwardSignals(cmd)
	stopTimer := startIdleFlush(idle, w)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// The pseudo terminal reports EIO when the child closes its end. That
		// is the normal end of the stream, not a fault.
		_, _ = io.Copy(w, ptmx)
	}()
	// The keyboard copy is not in the wait group. A read from the keyboard
	// blocks until the user types, and the user has nothing left to type once
	// the child is gone.
	go func() { _, _ = io.Copy(ptmx, stdin) }()

	waitErr := cmd.Wait()
	// Closing our end of the pseudo terminal ends the output copy.
	_ = ptmx.Close()
	wg.Wait()
	stopTimer()
	stopSignals()

	closeErr := w.Close()
	res.ExitCode = exitCode(cmd, waitErr)
	res.Hits = w.Hits()
	if ctx.Err() != nil {
		return res, ctx.Err()
	}
	return res, closeErr
}

// startIdleFlush runs a timer that flushes each writer while the stream is
// quiet. It returns a function that stops the timer.
func startIdleFlush(every time.Duration, writers ...*redact.Writer) func() {
	done := make(chan struct{})
	var once sync.Once
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				for _, w := range writers {
					_ = w.FlushIdle()
				}
			}
		}
	}()
	return func() { once.Do(func() { close(done) }) }
}

// forwardSignals passes a signal from the parent to the child.
//
// The child is the program the user meant to run, so the child must decide
// what a signal means. A build tool that catches SIGINT to clean up must still
// get the chance to do it.
func forwardSignals(cmd *exec.Cmd) func() {
	ch := make(chan os.Signal, 8)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP,
		syscall.SIGQUIT, syscall.SIGUSR1, syscall.SIGUSR2)
	done := make(chan struct{})
	var once sync.Once
	go func() {
		for {
			select {
			case <-done:
				return
			case s := <-ch:
				if cmd.Process != nil {
					_ = cmd.Process.Signal(s)
				}
			}
		}
	}()
	return func() {
		once.Do(func() {
			signal.Stop(ch)
			close(done)
		})
	}
}

// followResize keeps the size of the pseudo terminal equal to the size of the
// real terminal. Without it a program that draws a table draws it at the wrong
// width.
func followResize(ptmx *os.File, stdout io.Writer) func() {
	f, ok := stdout.(*os.File)
	if !ok {
		return func() {}
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	done := make(chan struct{})
	var once sync.Once
	resize := func() { _ = pty.InheritSize(f, ptmx) }
	resize()
	go func() {
		for {
			select {
			case <-done:
				return
			case <-ch:
				resize()
			}
		}
	}()
	return func() {
		once.Do(func() {
			signal.Stop(ch)
			close(done)
		})
	}
}

// makeRaw puts the terminal in raw mode and returns the restore function.
func makeRaw(stdin io.Reader) (func(), bool) {
	f, ok := stdin.(*os.File)
	if !ok {
		return nil, false
	}
	fd := int(f.Fd())
	if !term.IsTerminal(fd) {
		return nil, false
	}
	old, err := term.MakeRaw(fd)
	if err != nil {
		return nil, false
	}
	return func() { _ = term.Restore(fd, old) }, true
}

// isTerminal reports whether a stream is a real terminal.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// isStartFailure reports whether the child never ran.
func isStartFailure(err error) bool {
	if err == nil {
		return false
	}
	var ee *exec.ExitError
	return !errors.As(err, &ee)
}

// exitCode turns the result of Wait into the number a shell reports.
func exitCode(cmd *exec.Cmd, err error) int {
	if cmd.ProcessState != nil {
		if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal())
		}
		return cmd.ProcessState.ExitCode()
	}
	if err != nil {
		return 1
	}
	return 0
}

// mergeHits adds two hit counts together.
func mergeHits(a, b map[string]int) map[string]int {
	out := make(map[string]int, len(a)+len(b))
	for k, v := range a {
		out[k] += v
	}
	for k, v := range b {
		out[k] += v
	}
	return out
}

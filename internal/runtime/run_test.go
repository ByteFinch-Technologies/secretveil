package runtime

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The secret in these tests is long enough that the filter does not skip it,
// and it is not a real credential.
const testSecret = "sk-live-abcdef0123456789"

// safeBuffer is a buffer that more than one goroutine can write to. The idle
// timer and the child both write while the test reads.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
	// wrote is closed after the first write, so a test can wait for output
	// without a sleep.
	wroteOnce sync.Once
	wrote     chan struct{}
}

func newSafeBuffer() *safeBuffer {
	return &safeBuffer{wrote: make(chan struct{})}
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	n, err := s.buf.Write(p)
	s.mu.Unlock()
	if n > 0 {
		s.wroteOnce.Do(func() { close(s.wrote) })
	}
	return n, err
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// runSh runs a shell command through the runtime and returns the result.
func runSh(t *testing.T, script string, cfg Config) (*Result, string, string) {
	t.Helper()
	out, errOut := newSafeBuffer(), newSafeBuffer()
	cfg.Args = []string{"/bin/sh", "-c", script}
	cfg.Stdin = strings.NewReader("")
	cfg.Stdout = out
	cfg.Stderr = errOut
	cfg.NoPTY = true
	res, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("the runtime failed: %v", err)
	}
	return res, out.String(), errOut.String()
}

func TestTheChildSeesTheResolvedValue(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".env", "API_KEY=sv://api_key\n")
	st := memStore(t, map[string]string{"api_key": testSecret})

	got, err := Resolve(context.Background(), st, Options{Dir: dir, Parent: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	// The child writes the value to a file, which the filter does not touch.
	// This proves the child really received the secret.
	proof := filepath.Join(dir, "proof")
	res, _, _ := runSh(t, "printf %s \"$API_KEY\" > "+proof, Config{
		Env: got.Env, Values: got.Values,
	})
	if res.ExitCode != 0 {
		t.Fatalf("the child exited with %d", res.ExitCode)
	}
	body, err := os.ReadFile(proof)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != testSecret {
		t.Fatalf("the child received %q", string(body))
	}
}

func TestTheSecretDoesNotReachStdout(t *testing.T) {
	res, out, _ := runSh(t, `echo "the key is $API_KEY today"`, Config{
		Env:    append(os.Environ(), "API_KEY="+testSecret),
		Values: map[string]string{"api_key": testSecret},
	})
	if strings.Contains(out, testSecret) {
		t.Fatalf("the secret reached the output: %q", out)
	}
	if !strings.Contains(out, "sv://api_key") {
		t.Fatalf("the placeholder is missing from %q", out)
	}
	if !strings.Contains(out, "the key is") || !strings.Contains(out, "today") {
		t.Fatalf("the filter damaged the ordinary text: %q", out)
	}
	if res.Hits["api_key"] != 1 {
		t.Fatalf("the hit count is %v", res.Hits)
	}
}

func TestTheSecretDoesNotReachStderr(t *testing.T) {
	_, _, errOut := runSh(t, `echo "failed with $API_KEY" >&2`, Config{
		Env:    append(os.Environ(), "API_KEY="+testSecret),
		Values: map[string]string{"api_key": testSecret},
	})
	if strings.Contains(errOut, testSecret) {
		t.Fatalf("the secret reached the error stream: %q", errOut)
	}
	if !strings.Contains(errOut, "sv://api_key") {
		t.Fatalf("the placeholder is missing from %q", errOut)
	}
}

func TestABase64FormOfTheSecretIsAlsoRemoved(t *testing.T) {
	_, out, _ := runSh(t, `printf 'Authorization: Basic %s\n' "$(printf %s "$API_KEY" | base64)"`, Config{
		Env:    append(os.Environ(), "API_KEY="+testSecret),
		Values: map[string]string{"api_key": testSecret},
	})
	if strings.Contains(out, "c2stbGl2ZS1hYmNkZWYwMTIzNDU2Nzg5") {
		t.Fatalf("the encoded secret reached the output: %q", out)
	}
	if !strings.Contains(out, "Authorization: Basic") {
		t.Fatalf("the filter damaged the ordinary text: %q", out)
	}
}

func TestTheExitCodeIsPassedOn(t *testing.T) {
	for _, want := range []int{0, 1, 42, 255} {
		res, _, _ := runSh(t, "exit "+itoa(want), Config{})
		if res.ExitCode != want {
			t.Fatalf("the child exited with %d, want %d", res.ExitCode, want)
		}
	}
}

func TestASignalGivesTheShellExitCode(t *testing.T) {
	// 128 plus SIGTERM, which is 15.
	res, _, _ := runSh(t, "kill -TERM $$; sleep 5", Config{})
	if res.ExitCode != 143 {
		t.Fatalf("the child exited with %d, want 143", res.ExitCode)
	}
}

func TestAMissingProgramIsAnError(t *testing.T) {
	_, err := Run(context.Background(), Config{
		Args:   []string{"secretveil-no-such-program"},
		Stdout: newSafeBuffer(),
		Stderr: newSafeBuffer(),
		Stdin:  strings.NewReader(""),
		NoPTY:  true,
	})
	if err == nil {
		t.Fatal("a program that does not exist must be an error")
	}
}

func TestNoCommandIsAnError(t *testing.T) {
	if _, err := Run(context.Background(), Config{}); err != ErrNoCommand {
		t.Fatalf("the error is %v, want ErrNoCommand", err)
	}
}

func TestTheWorkingDirectoryIsUsed(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "marker.txt", "here")
	_, out, _ := runSh(t, "cat marker.txt", Config{Dir: dir})
	if !strings.Contains(out, "here") {
		t.Fatalf("the child ran somewhere else: %q", out)
	}
}

func TestAPromptWithoutANewlineStillArrives(t *testing.T) {
	// This is the property the idle timer exists for. The child prints a
	// prompt with no newline and then waits. Without the timer the filter
	// holds the last bytes and the user sees nothing.
	out := newSafeBuffer()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = Run(context.Background(), Config{
			Args:      []string{"/bin/sh", "-c", `printf 'Password: '; sleep 2`},
			Env:       os.Environ(),
			Values:    map[string]string{"api_key": testSecret},
			Stdin:     strings.NewReader(""),
			Stdout:    out,
			Stderr:    newSafeBuffer(),
			NoPTY:     true,
			IdleFlush: 20 * time.Millisecond,
		})
	}()

	select {
	case <-out.wrote:
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("the prompt never reached the output")
	}
	if got := out.String(); got != "Password: " {
		t.Fatalf("the output is %q, want the whole prompt", got)
	}
	<-done
}

func TestAPartialSecretIsStillHeldBack(t *testing.T) {
	// The child prints the first half of the secret and waits. The idle timer
	// must not release it, because the second half can still arrive.
	half := testSecret[:len(testSecret)/2]
	out := newSafeBuffer()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = Run(context.Background(), Config{
			Args:      []string{"/bin/sh", "-c", `printf 'start ' ; printf %s "$HALF"; sleep 1`},
			Env:       append(os.Environ(), "HALF="+half),
			Values:    map[string]string{"api_key": testSecret},
			Stdin:     strings.NewReader(""),
			Stdout:    out,
			Stderr:    newSafeBuffer(),
			NoPTY:     true,
			IdleFlush: 20 * time.Millisecond,
		})
	}()

	select {
	case <-out.wrote:
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("nothing reached the output")
	}
	time.Sleep(200 * time.Millisecond)
	if got := out.String(); got != "start " {
		t.Fatalf("the output is %q, want only the text before the secret", got)
	}
	<-done
}

func TestAShortValueIsReportedAndNotRemoved(t *testing.T) {
	res, out, _ := runSh(t, `echo "mode is $MODE"`, Config{
		Env:    append(os.Environ(), "MODE=dev"),
		Values: map[string]string{"mode": "dev"},
	})
	if !strings.Contains(out, "mode is dev") {
		t.Fatalf("the filter removed a short value: %q", out)
	}
	if len(res.Skipped) != 1 || res.Skipped[0] != "mode" {
		t.Fatalf("the skipped list is %v, want [mode]", res.Skipped)
	}
}

func TestTheOutputIsUnchangedWhenThereIsNoSecret(t *testing.T) {
	_, out, _ := runSh(t, `printf 'hello world\n'`, Config{})
	if out != "hello world\n" {
		t.Fatalf("the output is %q", out)
	}
}

func TestAPseudoTerminalRunFiltersTheOutput(t *testing.T) {
	// The test has no real terminal, so it asks for one. The child still gets
	// a pseudo terminal, which is the part under test.
	out := newSafeBuffer()
	cfg := Config{
		Args:     []string{"/bin/sh", "-c", `echo "the key is $API_KEY"; test -t 1 && echo TTY`},
		Env:      append(os.Environ(), "API_KEY="+testSecret),
		Values:   map[string]string{"api_key": testSecret},
		Stdin:    strings.NewReader(""),
		Stdout:   out,
		Stderr:   newSafeBuffer(),
		ForcePTY: true,
	}
	res, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("the runtime failed: %v", err)
	}
	got := out.String()
	if strings.Contains(got, testSecret) {
		t.Fatalf("the secret reached the terminal: %q", got)
	}
	if !strings.Contains(got, "sv://api_key") {
		t.Fatalf("the placeholder is missing from %q", got)
	}
	if !strings.Contains(got, "TTY") {
		t.Fatalf("the child did not get a terminal: %q", got)
	}
	if !res.PTY {
		t.Fatal("the result does not report a pseudo terminal")
	}
	if res.ExitCode != 0 {
		t.Fatalf("the child exited with %d", res.ExitCode)
	}
}

// TestAPseudoTerminalRemovesAMultiLineValue is the case of a private key in a
// .env file. The terminal driver prints each "\n" of the value as "\r\n", so
// the value itself never matches on a pseudo terminal. The child also prints
// one body line alone, which is the key material without its armour.
func TestAPseudoTerminalRemovesAMultiLineValue(t *testing.T) {
	const key = "-----BEGIN FAKE KEY-----\n" +
		"UHR5TXVsdGlMaW5lT25lLUg4dlE0bVI2dFc5eA\n" +
		"UHR5TXVsdGlMaW5lVHdvLUIzbkw3cEs1elgyYw\n" +
		"-----END FAKE KEY-----"
	body := strings.Split(key, "\n")[1:3]

	out := newSafeBuffer()
	cfg := Config{
		Args:     []string{"/bin/sh", "-c", `printf '%s\n' "$TLS_KEY"; printf '%s\n' "$TLS_KEY" | sed -n 3p`},
		Env:      append(os.Environ(), "TLS_KEY="+key),
		Values:   map[string]string{"tls_key": key},
		Stdin:    strings.NewReader(""),
		Stdout:   out,
		Stderr:   newSafeBuffer(),
		ForcePTY: true,
	}
	res, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("the runtime failed: %v", err)
	}
	got := out.String()
	for _, line := range body {
		if strings.Contains(got, line) {
			t.Fatalf("a line of the key reached the terminal: %q", got)
		}
	}
	if !strings.Contains(got, "sv://tls_key") {
		t.Fatalf("the placeholder is missing from %q", got)
	}
	if !res.PTY {
		t.Fatal("the result does not report a pseudo terminal")
	}
}

// TestAPseudoTerminalRunGetsTheEndOfAPipedInput guards input from a pipe or a
// file when the output is a terminal, as in "psql < dump.sql". The child must
// read the input directly and get its end. A copy into the pseudo terminal
// never sent the end, so the child waited forever.
func TestAPseudoTerminalRunGetsTheEndOfAPipedInput(t *testing.T) {
	out := newSafeBuffer()
	cfg := Config{
		Args:     []string{"/bin/sh", "-c", `cat; echo "input ended"; test -t 1 && echo TTY`},
		Env:      os.Environ(),
		Values:   map[string]string{"api_key": testSecret},
		Stdin:    strings.NewReader("one line of input\n"),
		Stdout:   out,
		Stderr:   newSafeBuffer(),
		ForcePTY: true,
	}
	// Run does not stop a child that waits, so the limit is here. Without
	// it, the fault hangs the whole test run instead of failing this test.
	type outcome struct {
		res *Result
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := Run(context.Background(), cfg)
		done <- outcome{res, err}
	}()
	var res *Result
	select {
	case o := <-done:
		if o.err != nil {
			t.Fatalf("the runtime failed: %v\n%q", o.err, out.String())
		}
		res = o.res
	case <-time.After(10 * time.Second):
		t.Fatalf("the child still waits for the end of the input: %q", out.String())
	}
	got := out.String()
	if !strings.Contains(got, "input ended") {
		t.Fatalf("the child did not get the end of the input: %q", got)
	}
	if n := strings.Count(got, "one line of input"); n != 1 {
		t.Fatalf("the input shows %d times, not once: %q", n, got)
	}
	if !strings.Contains(got, "TTY") {
		t.Fatalf("the output is not a terminal: %q", got)
	}
	if res.ExitCode != 0 {
		t.Fatalf("the child exited with %d", res.ExitCode)
	}
}

// TestAProgramLeftInTheBackgroundDoesNotHoldTheRun guards the pipe path. A
// child that starts a program in the background and exits leaves that program
// with the output pipes. The run must end a short time after the child, and
// must keep the exit code of the child.
func TestAProgramLeftInTheBackgroundDoesNotHoldTheRun(t *testing.T) {
	for _, tc := range []struct {
		script string
		code   int
	}{
		{`sleep 20 & echo "parent done"`, 0},
		{`sleep 20 & echo "parent done"; exit 3`, 3},
	} {
		out := newSafeBuffer()
		type outcome struct {
			res *Result
			err error
		}
		done := make(chan outcome, 1)
		start := time.Now()
		go func() {
			res, err := Run(context.Background(), Config{
				Args:   []string{"/bin/sh", "-c", tc.script},
				Env:    os.Environ(),
				Stdin:  strings.NewReader(""),
				Stdout: out,
				Stderr: newSafeBuffer(),
				NoPTY:  true,
			})
			done <- outcome{res, err}
		}()
		select {
		case o := <-done:
			if o.err != nil {
				t.Fatalf("%s: the runtime failed: %v", tc.script, o.err)
			}
			if o.res.ExitCode != tc.code {
				t.Fatalf("%s: the exit code is %d, not %d", tc.script, o.res.ExitCode, tc.code)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: the run still waits for the program in the background", tc.script)
		}
		if took := time.Since(start); took > drainGrace+3*time.Second {
			t.Fatalf("%s: the run took %v", tc.script, took)
		}
		if !strings.Contains(out.String(), "parent done") {
			t.Fatalf("%s: the output is lost: %q", tc.script, out.String())
		}
	}
}

// itoa turns a small number into text without a dependency.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestAPseudoTerminalKeepsTheLastLine guards the drain. The child writes many
// lines and exits at once, so bytes are still in the pseudo terminal when
// cmd.Wait returns. A close before the copy finished threw those bytes away,
// and the last lines of a program went missing with nothing to say they had.
//
// The count is high enough to fill the buffer of the pseudo terminal more than
// once, so a partial copy cannot pass by luck.
func TestAPseudoTerminalKeepsTheLastLine(t *testing.T) {
	const lines = 500
	out := newSafeBuffer()
	cfg := Config{
		Args: []string{"/bin/sh", "-c",
			`i=1; while [ $i -le ` + itoa(lines) + ` ]; do echo "line $i of a program that stops"; i=$((i+1)); done`},
		Env:      os.Environ(),
		Values:   map[string]string{"api_key": testSecret},
		Stdin:    strings.NewReader(""),
		Stdout:   out,
		Stderr:   newSafeBuffer(),
		ForcePTY: true,
	}
	res, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("the runtime failed: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("the child exited with %d", res.ExitCode)
	}
	got := out.String()
	// The last line is the one a close-first drain loses.
	last := "line " + itoa(lines) + " of a program that stops"
	if !strings.Contains(got, last) {
		t.Fatalf("the last line is missing. The output ends with %q",
			tail(got, 120))
	}
	// Every line has to be there, not only the last one.
	for i := 1; i <= lines; i++ {
		if !strings.Contains(got, "line "+itoa(i)+" of a program that stops") {
			t.Fatalf("line %d is missing from an output of %d bytes", i, len(got))
		}
	}
}

// tail returns the last n bytes of s, for a message that has to stay short.
func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

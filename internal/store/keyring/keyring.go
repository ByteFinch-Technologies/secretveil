// Package keyring stores one short string in the operating system keyring.
//
// It does not store a secret value. It stores the key that opens the encrypted
// file, and that key is 74 characters. The limit is deliberate.
//
// The macOS "security" command reads a password from its prompt, and the
// prompt buffer holds 128 bytes. A longer value is cut without any warning and
// without any error code. A measurement on macOS 15 confirmed this: a 129 byte
// value came back as 128 bytes with exit code 0. The other way to write a
// value is to put it in the command line, and every user on the machine can
// then read it with "ps". Neither path is safe for a real secret.
//
// So this package refuses a value that is longer than MaxLen or that holds a
// newline, and the secrets themselves live in the encrypted file instead.
package keyring

import (
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// MaxLen is the largest value this package accepts. See the package comment.
const MaxLen = 128

// service is the keyring service name for every entry the program writes.
const service = "secretveil"

// ErrNotFound means the entry is not in the keyring.
var ErrNotFound = errors.New("no such keyring entry")

// Keyring is the operating system keyring.
type Keyring interface {
	Get(name string) (string, error)
	Set(name, value string) error
	Delete(name string) error
	Available() bool
	Name() string
}

// New returns the keyring for this operating system. The result is never nil.
// Call Available before use.
func New() Keyring {
	switch runtime.GOOS {
	case "darwin":
		return macOS{}
	case "linux":
		return libsecret{}
	default:
		return unsupported{}
	}
}

// checkValue rejects a value that the backend cannot carry without damage.
func checkValue(value string) error {
	if value == "" {
		return errors.New("the keyring value is empty")
	}
	if len(value) > MaxLen {
		return fmt.Errorf("the keyring value is %d bytes, and the limit is %d", len(value), MaxLen)
	}
	if strings.ContainsAny(value, "\n\r") {
		return errors.New("the keyring value holds a line break")
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] > 0x7e {
			return errors.New("the keyring value holds a byte that is not printable ASCII")
		}
	}
	return nil
}

func checkName(name string) error {
	if name == "" || len(name) > 200 {
		return fmt.Errorf("bad keyring entry name: %q", name)
	}
	if strings.ContainsAny(name, "\n\r\x00") {
		return fmt.Errorf("bad keyring entry name: %q", name)
	}
	return nil
}

// ---------------------------------------------------------------- macOS

type macOS struct{}

func (macOS) Name() string { return "macos-keychain" }

func (macOS) Available() bool {
	_, err := exec.LookPath("security")
	return err == nil
}

func (m macOS) Get(name string) (string, error) {
	if err := checkName(name); err != nil {
		return "", err
	}
	out, err := exec.Command("security", "find-generic-password",
		"-s", service, "-a", name, "-w").Output()
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	// The command adds one line ending. A stored value never holds one,
	// because Set rejects it.
	return strings.TrimRight(string(out), "\r\n"), nil
}

func (m macOS) Set(name, value string) error {
	if err := checkName(name); err != nil {
		return err
	}
	if err := checkValue(value); err != nil {
		return err
	}
	// The value goes in on standard input, never in the command line, so it
	// does not appear in the process list. The prompt asks for the value and
	// then asks again, so the program writes it twice.
	cmd := exec.Command("security", "add-generic-password",
		"-U", "-s", service, "-a", name,
		"-D", "secretveil file key", "-w")
	cmd.Stdin = strings.NewReader(value + "\n" + value + "\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("the macOS keychain refused the write: %s", firstLine(out))
	}
	// Read the value back. A silent cut is the failure this package exists to
	// prevent, so the program proves the write instead of trusting it.
	got, err := m.Get(name)
	if err != nil {
		return fmt.Errorf("the macOS keychain accepted the write but the value is not there: %w", err)
	}
	if got != value {
		_ = m.Delete(name)
		return fmt.Errorf("the macOS keychain changed the value on write: %d bytes in, %d bytes out",
			len(value), len(got))
	}
	return nil
}

func (macOS) Delete(name string) error {
	if err := checkName(name); err != nil {
		return err
	}
	// A missing entry is not an error.
	_ = exec.Command("security", "delete-generic-password",
		"-s", service, "-a", name).Run()
	return nil
}

// ---------------------------------------------------------------- Linux

type libsecret struct{}

func (libsecret) Name() string { return "linux-libsecret" }

func (libsecret) Available() bool {
	if _, err := exec.LookPath("secret-tool"); err != nil {
		return false
	}
	// A headless box has the command but no running keyring daemon. A lookup
	// of an absent entry is cheap and it proves the daemon answers.
	err := exec.Command("secret-tool", "lookup",
		"service", service, "account", "secretveil.probe").Run()
	if err == nil {
		return true
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		// Exit code 1 means "not found", and that is a working daemon.
		return ee.ExitCode() == 1
	}
	return false
}

func (l libsecret) Get(name string) (string, error) {
	if err := checkName(name); err != nil {
		return "", err
	}
	out, err := exec.Command("secret-tool", "lookup",
		"service", service, "account", name).Output()
	if err != nil || len(out) == 0 {
		return "", fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	return strings.TrimRight(string(out), "\r\n"), nil
}

func (l libsecret) Set(name, value string) error {
	if err := checkName(name); err != nil {
		return err
	}
	if err := checkValue(value); err != nil {
		return err
	}
	cmd := exec.Command("secret-tool", "store",
		"--label=secretveil file key",
		"service", service, "account", name)
	cmd.Stdin = strings.NewReader(value)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("the Linux keyring refused the write: %s", firstLine(out))
	}
	got, err := l.Get(name)
	if err != nil {
		return fmt.Errorf("the Linux keyring accepted the write but the value is not there: %w", err)
	}
	if got != value {
		_ = l.Delete(name)
		return fmt.Errorf("the Linux keyring changed the value on write: %d bytes in, %d bytes out",
			len(value), len(got))
	}
	return nil
}

func (libsecret) Delete(name string) error {
	if err := checkName(name); err != nil {
		return err
	}
	_ = exec.Command("secret-tool", "clear",
		"service", service, "account", name).Run()
	return nil
}

// ---------------------------------------------------------------- other

type unsupported struct{}

func (unsupported) Name() string    { return "none" }
func (unsupported) Available() bool { return false }
func (unsupported) Get(string) (string, error) {
	return "", errors.New("this operating system has no keyring backend yet")
}
func (unsupported) Set(string, string) error {
	return errors.New("this operating system has no keyring backend yet")
}
func (unsupported) Delete(string) error { return nil }

// Fake is an in-memory keyring for tests.
type Fake struct {
	Values   map[string]string
	Unusable bool
	// Truncate copies the macOS fault, so a test can prove the read back check
	// catches it.
	Truncate int
}

// NewFake returns an empty fake keyring.
func NewFake() *Fake { return &Fake{Values: map[string]string{}} }

func (f *Fake) Name() string    { return "fake" }
func (f *Fake) Available() bool { return !f.Unusable }

func (f *Fake) Get(name string) (string, error) {
	v, ok := f.Values[name]
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	return v, nil
}

func (f *Fake) Set(name, value string) error {
	if err := checkName(name); err != nil {
		return err
	}
	if err := checkValue(value); err != nil {
		return err
	}
	stored := value
	if f.Truncate > 0 && len(stored) > f.Truncate {
		stored = stored[:f.Truncate]
	}
	f.Values[name] = stored
	if stored != value {
		delete(f.Values, name)
		return fmt.Errorf("the fake keyring changed the value on write: %d bytes in, %d bytes out",
			len(value), len(stored))
	}
	return nil
}

func (f *Fake) Delete(name string) error {
	delete(f.Values, name)
	return nil
}

func firstLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		s = "no message"
	}
	return s
}

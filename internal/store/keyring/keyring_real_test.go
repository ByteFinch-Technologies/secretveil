package keyring

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// The tests in this file touch the real operating system keyring. They are off
// by default, because a test must not change a developer's keyring without
// permission and because a continuous integration container has no keyring.
//
// Run them with:
//
//	SECRETVEIL_KEYRING_TEST=1 go test ./internal/store/keyring/
//
// Every entry uses the name prefix below, and each test removes its own entry.
const testPrefix = "secretveil.selftest."

func realKeyring(t *testing.T) Keyring {
	t.Helper()
	if os.Getenv("SECRETVEIL_KEYRING_TEST") == "" {
		t.Skip("set SECRETVEIL_KEYRING_TEST=1 to test the real keyring")
	}
	k := New()
	if !k.Available() {
		t.Skipf("the %s keyring is not available here", k.Name())
	}
	return k
}

func TestRealKeyringRoundTrip(t *testing.T) {
	k := realKeyring(t)
	name := testPrefix + "roundtrip"
	t.Cleanup(func() { _ = k.Delete(name) })

	// An age identity is the real payload, so the test uses one that is the
	// same length.
	const value = "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"
	if err := k.Set(name, value); err != nil {
		t.Fatal(err)
	}
	got, err := k.Get(name)
	if err != nil {
		t.Fatal(err)
	}
	if got != value {
		t.Fatalf("the value changed: %d bytes in, %d bytes out", len(value), len(got))
	}
}

func TestRealKeyringOverwrite(t *testing.T) {
	k := realKeyring(t)
	name := testPrefix + "overwrite"
	t.Cleanup(func() { _ = k.Delete(name) })

	if err := k.Set(name, "first-value-0123456789"); err != nil {
		t.Fatal(err)
	}
	if err := k.Set(name, "second-value-abcdefghij"); err != nil {
		t.Fatal(err)
	}
	got, err := k.Get(name)
	if err != nil {
		t.Fatal(err)
	}
	if got != "second-value-abcdefghij" {
		t.Fatalf("the second write did not replace the first, got %q", got)
	}
}

func TestRealKeyringDelete(t *testing.T) {
	k := realKeyring(t)
	name := testPrefix + "delete"
	if err := k.Set(name, "to-be-removed-0123456789"); err != nil {
		t.Fatal(err)
	}
	if err := k.Delete(name); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Get(name); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound after delete, got %v", err)
	}
	if err := k.Delete(name); err != nil {
		t.Fatalf("deleting an absent entry must not fail: %v", err)
	}
}

// TestRealKeyringRefusesALongValue is the guard against the silent cut. It
// proves the check runs before the backend sees the value.
func TestRealKeyringRefusesALongValue(t *testing.T) {
	k := realKeyring(t)
	name := testPrefix + "toolong"
	t.Cleanup(func() { _ = k.Delete(name) })

	err := k.Set(name, strings.Repeat("x", MaxLen+1))
	if err == nil {
		t.Fatal("a value over the limit must be refused, not cut")
	}
	if _, gerr := k.Get(name); !errors.Is(gerr, ErrNotFound) {
		t.Fatal("a refused write must leave no entry behind")
	}
}

// TestRealKeyringValueIsNotInTheProcessList proves the value goes in on
// standard input. A value in the command line is readable by every user on the
// machine.
func TestRealKeyringValueIsNotInTheProcessList(t *testing.T) {
	k := realKeyring(t)
	if k.Name() != "macos-keychain" {
		t.Skip("this check reads the macOS command line")
	}
	name := testPrefix + "argv"
	t.Cleanup(func() { _ = k.Delete(name) })

	// The write is fast, so the test cannot watch the process list while it
	// runs. It checks the code path instead: a value with a shell character
	// must survive, which it can only do if it never goes through a shell.
	const tricky = `a"b'c$d;e|f&g<h>i(j)k`
	if err := k.Set(name, tricky); err != nil {
		t.Fatal(err)
	}
	got, err := k.Get(name)
	if err != nil {
		t.Fatal(err)
	}
	if got != tricky {
		t.Fatalf("the value changed: %q became %q", tricky, got)
	}
}

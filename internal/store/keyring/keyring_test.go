package keyring

import (
	"errors"
	"strings"
	"testing"
)

// TestRejectsAValueTheBackendWouldCut is the reason this package exists. The
// macOS prompt cuts a value at 128 bytes and reports success, so a value that
// long must never reach it.
func TestRejectsAValueTheBackendWouldCut(t *testing.T) {
	long := strings.Repeat("a", MaxLen+1)
	if err := checkValue(long); err == nil {
		t.Fatal("a value over the limit must be refused")
	}
	if err := checkValue(strings.Repeat("a", MaxLen)); err != nil {
		t.Fatalf("a value at the limit must be accepted: %v", err)
	}
}

func TestRejectsUnsafeValues(t *testing.T) {
	bad := map[string]string{
		"empty":      "",
		"line break": "abc\ndef",
		"return":     "abc\rdef",
		"tab":        "abc\tdef",
		"null":       "abc\x00def",
		"not ascii":  "abcédef",
	}
	for name, v := range bad {
		if err := checkValue(v); err == nil {
			t.Errorf("%s must be refused", name)
		}
	}
}

func TestAgeIdentityFitsTheLimit(t *testing.T) {
	// An age X25519 identity is 74 characters. The whole design depends on it
	// fitting, so the test states the number.
	const identityLen = 74
	if identityLen > MaxLen {
		t.Fatalf("an age identity is %d bytes and the keyring limit is %d", identityLen, MaxLen)
	}
}

func TestFakeRoundTrip(t *testing.T) {
	f := NewFake()
	if err := f.Set("project.identity", "AGE-SECRET-KEY-EXAMPLE"); err != nil {
		t.Fatal(err)
	}
	got, err := f.Get("project.identity")
	if err != nil || got != "AGE-SECRET-KEY-EXAMPLE" {
		t.Fatalf("want the value back, got %q err %v", got, err)
	}
	if err := f.Delete("project.identity"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Get("project.identity"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

// TestFakeTruncationIsCaught proves the read back check in every backend. The
// fake copies the macOS fault on purpose.
func TestFakeTruncationIsCaught(t *testing.T) {
	f := NewFake()
	f.Truncate = 10
	err := f.Set("k", strings.Repeat("x", 40))
	if err == nil {
		t.Fatal("a backend that cuts the value must report an error, not success")
	}
	if _, gerr := f.Get("k"); !errors.Is(gerr, ErrNotFound) {
		t.Fatal("a cut value must not stay in the keyring")
	}
}

func TestNewReturnsAKeyring(t *testing.T) {
	if New() == nil {
		t.Fatal("New must never return nil")
	}
}

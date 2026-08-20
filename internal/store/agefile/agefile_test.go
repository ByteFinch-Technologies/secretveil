package agefile

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/ByteFinch-Technologies/secretveil/internal/store"
	"github.com/ByteFinch-Technologies/secretveil/internal/store/keyring"
)

func TestMain(m *testing.M) {
	// The age default takes about one second for each write on purpose. A
	// test does not need that cost.
	scryptWorkFactor = 10
	os.Exit(m.Run())
}

// clearEnv removes any real setting, so a developer's own environment cannot
// change the result of a test.
func clearEnv(t *testing.T) {
	t.Helper()
	t.Setenv(EnvIdentity, "")
	t.Setenv(EnvPassphrase, "")
	os.Unsetenv(EnvIdentity)
	os.Unsetenv(EnvPassphrase)
}

func newTestStore(t *testing.T) (*Store, *keyring.Fake, string) {
	t.Helper()
	clearEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, ".secretveil", FileName)
	ring := keyring.NewFake()
	return New(path, ring, "test.identity"), ring, path
}

func TestRoundTripWithKeyring(t *testing.T) {
	ctx := context.Background()
	s, ring, path := newTestStore(t)

	if err := s.Set(ctx, "db_password", "tr0ub4dor"); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, "db_password")
	if err != nil || got != "tr0ub4dor" {
		t.Fatalf("want tr0ub4dor, got %q err %v", got, err)
	}
	if len(ring.Values) != 1 {
		t.Fatalf("the keyring must hold exactly one entry, it holds %d", len(ring.Values))
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the encrypted file was not written: %v", err)
	}
}

// TestValueSurvivesAProcessRestart is the acceptance test named in the plan.
func TestValueSurvivesAProcessRestart(t *testing.T) {
	ctx := context.Background()
	s, ring, path := newTestStore(t)
	if err := s.Set(ctx, "jwt_secret", "a-long-secret-value"); err != nil {
		t.Fatal(err)
	}

	// A new Store with the same keyring stands for a new process.
	again := New(path, ring, "test.identity")
	got, err := again.Get(ctx, "jwt_secret")
	if err != nil || got != "a-long-secret-value" {
		t.Fatalf("the value did not survive: got %q err %v", got, err)
	}
}

// TestTheFileHoldsNoPlaintext is the property that matters. A grep for the
// secret in the file on disk must find nothing.
func TestTheFileHoldsNoPlaintext(t *testing.T) {
	ctx := context.Background()
	s, _, path := newTestStore(t)
	const secret = "tr0ub4dor-horse-battery"
	if err := s.Set(ctx, "db_password", secret); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(secret)) {
		t.Fatal("the encrypted file holds the plaintext secret")
	}
	if bytes.Contains(raw, []byte("db_password")) {
		t.Fatal("the encrypted file holds the reference name in plaintext")
	}
}

func TestFilePermissions(t *testing.T) {
	ctx := context.Background()
	s, _, path := newTestStore(t)
	if err := s.Set(ctx, "a", "b"); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := fi.Mode().Perm(); mode != 0o600 {
		t.Errorf("want file mode 0600, got %o", mode)
	}
	di, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if mode := di.Mode().Perm(); mode != 0o700 {
		t.Errorf("want directory mode 0700, got %o", mode)
	}
}

func TestPassphraseRoundTrip(t *testing.T) {
	ctx := context.Background()
	clearEnv(t)
	t.Setenv(EnvPassphrase, "correct horse battery staple")

	dir := t.TempDir()
	path := filepath.Join(dir, ".secretveil", FileName)
	// The keyring is unusable, which is the headless Linux case.
	ring := keyring.NewFake()
	ring.Unusable = true

	s := New(path, ring, "test.identity")
	if !s.Available() {
		t.Fatal("a passphrase must make the store available with no keyring")
	}
	if err := s.Set(ctx, "db_password", "hunter2"); err != nil {
		t.Fatal(err)
	}
	if len(ring.Values) != 0 {
		t.Fatal("the passphrase path must not write to the keyring")
	}

	again := New(path, ring, "test.identity")
	got, err := again.Get(ctx, "db_password")
	if err != nil || got != "hunter2" {
		t.Fatalf("want hunter2, got %q err %v", got, err)
	}
}

func TestIdentityFromEnvironment(t *testing.T) {
	ctx := context.Background()
	clearEnv(t)
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvIdentity, id.String())

	dir := t.TempDir()
	path := filepath.Join(dir, ".secretveil", FileName)
	ring := keyring.NewFake()
	ring.Unusable = true

	s := New(path, ring, "test.identity")
	if err := s.Set(ctx, "ci_token", "from-ci"); err != nil {
		t.Fatal(err)
	}
	again := New(path, ring, "test.identity")
	got, err := again.Get(ctx, "ci_token")
	if err != nil || got != "from-ci" {
		t.Fatalf("want from-ci, got %q err %v", got, err)
	}
}

// TestTheWrongKeyCannotOpenTheFile is the negative case. Without it the tests
// would pass even if the file were not really encrypted.
func TestTheWrongKeyCannotOpenTheFile(t *testing.T) {
	ctx := context.Background()
	s, _, path := newTestStore(t)
	if err := s.Set(ctx, "db_password", "hunter2"); err != nil {
		t.Fatal(err)
	}

	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	clearEnv(t)
	t.Setenv(EnvIdentity, other.String())

	blocked := keyring.NewFake()
	blocked.Unusable = true
	wrong := New(path, blocked, "test.identity")
	if _, err := wrong.Get(ctx, "db_password"); err == nil {
		t.Fatal("the wrong key must not open the file")
	}
}

func TestNoKeyGivesAClearMessage(t *testing.T) {
	ctx := context.Background()
	s, _, path := newTestStore(t)
	if err := s.Set(ctx, "db_password", "hunter2"); err != nil {
		t.Fatal(err)
	}

	clearEnv(t)
	blocked := keyring.NewFake()
	blocked.Unusable = true
	blind := New(path, blocked, "test.identity")

	_, err := blind.Get(ctx, "db_password")
	if err == nil {
		t.Fatal("a store with no key must fail")
	}
	if !strings.Contains(err.Error(), EnvPassphrase) {
		t.Errorf("the message must name the fix, it said: %v", err)
	}
}

func TestSetManyWritesOnce(t *testing.T) {
	ctx := context.Background()
	s, _, path := newTestStore(t)
	values := map[string]string{
		"db_password": "one",
		"jwt_secret":  "two",
		"api_key":     "three",
	}
	if err := s.SetMany(ctx, values); err != nil {
		t.Fatal(err)
	}
	again := New(path, s.ring, "test.identity")
	refs, err := again.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"api_key", "db_password", "jwt_secret"}
	if len(refs) != len(want) {
		t.Fatalf("want %v, got %v", want, refs)
	}
	for i := range want {
		if refs[i] != want[i] {
			t.Fatalf("want %v, got %v", want, refs)
		}
	}
	for ref, v := range values {
		got, err := again.Get(ctx, ref)
		if err != nil || got != v {
			t.Errorf("%s: want %q, got %q err %v", ref, v, got, err)
		}
	}
}

func TestDelete(t *testing.T) {
	ctx := context.Background()
	s, _, path := newTestStore(t)
	if err := s.Set(ctx, "gone", "x"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, "gone"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, "never_there"); err != nil {
		t.Fatalf("deleting an absent reference must not fail: %v", err)
	}
	again := New(path, s.ring, "test.identity")
	if _, err := again.Get(ctx, "gone"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want ErrNotFound after delete, got %v", err)
	}
}

func TestMissingFileIsEmptyNotAnError(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newTestStore(t)
	refs, err := s.List(ctx)
	if err != nil {
		t.Fatalf("a missing file must read as empty: %v", err)
	}
	if len(refs) != 0 {
		t.Fatalf("want no references, got %v", refs)
	}
}

func TestBadRefIsRefused(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newTestStore(t)
	if err := s.Set(ctx, "BAD REF", "x"); err == nil {
		t.Fatal("a bad reference must be refused")
	}
	if err := s.SetMany(ctx, map[string]string{"ok": "1", "BAD REF": "2"}); err == nil {
		t.Fatal("SetMany must refuse the whole batch when one reference is bad")
	}
}

// TestMultilineValueSurvives is the case the keyring cannot carry. It proves
// the encrypted file takes over that job.
func TestMultilineValueSurvives(t *testing.T) {
	ctx := context.Background()
	s, _, path := newTestStore(t)
	pem := "-----BEGIN RSA PRIVATE KEY-----\n" +
		strings.Repeat("this-is-not-a-key-it-is-a-test-fixture0\n", 40) +
		"-----END RSA PRIVATE KEY-----\n"
	if len(pem) <= keyring.MaxLen {
		t.Fatalf("the test value must be longer than the keyring limit, it is %d", len(pem))
	}
	if err := s.Set(ctx, "private_key", pem); err != nil {
		t.Fatal(err)
	}
	again := New(path, s.ring, "test.identity")
	got, err := again.Get(ctx, "private_key")
	if err != nil {
		t.Fatal(err)
	}
	if got != pem {
		t.Fatalf("the value changed: %d bytes in, %d bytes out", len(pem), len(got))
	}
}

// TestNoTemporaryFileIsLeftBehind guards the atomic write.
func TestNoTemporaryFileIsLeftBehind(t *testing.T) {
	ctx := context.Background()
	s, _, path := newTestStore(t)
	if err := s.Set(ctx, "a", "b"); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("a temporary file was left behind: %s", e.Name())
		}
	}
	if len(entries) != 1 {
		t.Errorf("want exactly one file in the directory, got %d", len(entries))
	}
}

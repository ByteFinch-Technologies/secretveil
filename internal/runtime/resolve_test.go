package runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ByteFinch-Technologies/secretveil/internal/store"
)

// write puts a file in a directory and fails the test if it cannot.
func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// memStore returns a store that holds the given references.
func memStore(t *testing.T, kv map[string]string) *store.Mem {
	t.Helper()
	m := store.NewMem()
	for k, v := range kv {
		if err := m.Set(context.Background(), k, v); err != nil {
			t.Fatal(err)
		}
	}
	return m
}

// value returns the value of a key in an environment list.
func value(env []string, key string) (string, bool) {
	out, ok := "", false
	for _, e := range env {
		if k, v, cut := strings.Cut(e, "="); cut && k == key {
			// A later entry wins, which is what execve does.
			out, ok = v, true
		}
	}
	return out, ok
}

func TestAHandleBecomesTheRealValue(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".env", "API_KEY=sv://api_key\nPORT=3000\n")
	st := memStore(t, map[string]string{"api_key": "sk-live-0123456789"})

	res, err := Resolve(context.Background(), st, Options{Dir: dir, Parent: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := value(res.Env, "API_KEY"); got != "sk-live-0123456789" {
		t.Fatalf("API_KEY is %q", got)
	}
	if got, _ := value(res.Env, "PORT"); got != "3000" {
		t.Fatalf("PORT is %q", got)
	}
	if res.Handles != 1 {
		t.Fatalf("the pass replaced %d handles, want 1", res.Handles)
	}
	if res.Values["api_key"] != "sk-live-0123456789" {
		t.Fatal("the value for the filter is missing")
	}
}

func TestAHandleInsideALongerValueIsReplaced(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".env", "DATABASE_URL=postgres://app:sv://db_password@localhost:5432/app\n")
	st := memStore(t, map[string]string{"db_password": "hunter2hunter2"})

	res, err := Resolve(context.Background(), st, Options{Dir: dir, Parent: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	want := "postgres://app:hunter2hunter2@localhost:5432/app"
	if got, _ := value(res.Env, "DATABASE_URL"); got != want {
		t.Fatalf("DATABASE_URL is %q, want %q", got, want)
	}
}

func TestTheParentEnvironmentWins(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".env", "API_KEY=sv://api_key\n")
	st := memStore(t, map[string]string{"api_key": "from-the-store"})

	res, err := Resolve(context.Background(), st, Options{
		Dir:    dir,
		Parent: []string{"API_KEY=from-the-shell"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := value(res.Env, "API_KEY"); got != "from-the-shell" {
		t.Fatalf("API_KEY is %q, want the value from the shell", got)
	}
	if len(res.Skipped) != 1 || res.Skipped[0] != "API_KEY" {
		t.Fatalf("the skipped list is %v", res.Skipped)
	}
	// The store was never read, so the filter has nothing to hide.
	if len(res.Values) != 0 {
		t.Fatalf("the pass read %v from the store and did not need to", res.Values)
	}
}

func TestTheLocalFileWinsOverTheMainFile(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".env", "API_KEY=sv://api_key\nPORT=3000\n")
	write(t, dir, ".env.local", "PORT=4000\n")
	st := memStore(t, map[string]string{"api_key": "sk-live-0123456789"})

	res, err := Resolve(context.Background(), st, Options{Dir: dir, Parent: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := value(res.Env, "PORT"); got != "4000" {
		t.Fatalf("PORT is %q, want the value from .env.local", got)
	}
	if len(res.Files) != 2 {
		t.Fatalf("the pass read %v", res.Files)
	}
}

func TestAMissingFileIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	res, err := Resolve(context.Background(), store.NewMem(), Options{Dir: dir, Parent: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 0 || len(res.Env) != 0 {
		t.Fatalf("the pass found %v and %v", res.Files, res.Env)
	}
}

func TestAMissingReferenceIsReported(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".env", "API_KEY=sv://api_key\nOTHER=sv://other\n")
	st := memStore(t, map[string]string{"other": "0123456789"})

	res, err := Resolve(context.Background(), st, Options{Dir: dir, Parent: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Missing) != 1 || res.Missing[0] != "api_key" {
		t.Fatalf("the missing list is %v, want [api_key]", res.Missing)
	}
	// The handle stays in place, so the child fails with a message that names
	// the reference instead of an empty string.
	if got, _ := value(res.Env, "API_KEY"); got != "sv://api_key" {
		t.Fatalf("API_KEY is %q", got)
	}
}

func TestTheSameHandleIsReadOnce(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".env", "A=sv://shared\nB=sv://shared\nC=sv://shared\n")
	st := &countingStore{Mem: memStore(t, map[string]string{"shared": "0123456789"})}

	res, err := Resolve(context.Background(), st, Options{Dir: dir, Parent: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if st.reads != 1 {
		t.Fatalf("the pass read the store %d times, want 1", st.reads)
	}
	if res.Handles != 3 {
		t.Fatalf("the pass replaced %d handles, want 3", res.Handles)
	}
}

func TestAQuotedMultilineValueSurvives(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".env", "KEY=\"sv://pem\"\n")
	pem := "-----BEGIN KEY-----\nabcdefgh\n-----END KEY-----"
	st := memStore(t, map[string]string{"pem": pem})

	res, err := Resolve(context.Background(), st, Options{Dir: dir, Parent: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := value(res.Env, "KEY"); got != pem {
		t.Fatalf("KEY is %q", got)
	}
}

// countingStore counts the reads, so a test can prove the cache works.
type countingStore struct {
	*store.Mem
	reads int
}

func (c *countingStore) Get(ctx context.Context, ref string) (string, error) {
	c.reads++
	return c.Mem.Get(ctx, ref)
}

// badStore is a store that opened with the wrong key. Every read fails, and
// none of the failures is ErrNotFound.
type badStore struct{ err error }

func (b badStore) Get(context.Context, string) (string, error) { return "", b.err }
func (b badStore) Set(context.Context, string, string) error   { return b.err }
func (b badStore) List(context.Context) ([]string, error)      { return nil, b.err }
func (b badStore) Delete(context.Context, string) error        { return b.err }
func (b badStore) Name() string                                { return "bad" }
func (b badStore) Available() bool                             { return true }

func TestAStoreThatDoesNotReadIsNotAMissingValue(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".env", "API_KEY=sv://api_key\nDB_PASSWORD=sv://db_password\n")
	wrongKey := errors.New("the key does not open this store")

	res, err := Resolve(context.Background(), badStore{err: wrongKey}, Options{Dir: dir, Parent: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	// Both references look missing, because the store answered neither.
	if len(res.Missing) != 2 {
		t.Fatalf("Missing holds %d references, want 2", len(res.Missing))
	}
	// The cause must survive, so the caller does not tell the developer to
	// set a value that is already in the store.
	if !errors.Is(res.Err, wrongKey) {
		t.Fatalf("Err is %v, want the store fault", res.Err)
	}
}

func TestAMissingReferenceIsNotAStoreFault(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".env", "API_KEY=sv://api_key\n")
	st := memStore(t, map[string]string{})

	res, err := Resolve(context.Background(), st, Options{Dir: dir, Parent: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Missing) != 1 {
		t.Fatalf("Missing holds %d references, want 1", len(res.Missing))
	}
	if res.Err != nil {
		t.Fatalf("Err is %v, want nothing", res.Err)
	}
}

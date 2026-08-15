package store

import (
	"context"
	"errors"
	"testing"
)

// roStore is a read only backend for the chain tests.
type roStore struct {
	name   string
	values map[string]string
	up     bool
}

func (r *roStore) Name() string    { return r.name }
func (r *roStore) Available() bool { return r.up }
func (r *roStore) Get(_ context.Context, ref string) (string, error) {
	v, ok := r.values[ref]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}
func (r *roStore) Set(context.Context, string, string) error { return ErrReadOnly }
func (r *roStore) Delete(context.Context, string) error      { return ErrReadOnly }
func (r *roStore) List(context.Context) ([]string, error) {
	out := []string{}
	for k := range r.values {
		out = append(out, k)
	}
	return out, nil
}

func TestValidRef(t *testing.T) {
	good := []string{"db_password", "a", "jwt-secret", "app.token", "x9"}
	bad := []string{"", "DB_PASSWORD", "db password", "db/password", "db$", "a\nb"}
	for _, r := range good {
		if !ValidRef(r) {
			t.Errorf("%q should be a valid reference", r)
		}
	}
	for _, r := range bad {
		if ValidRef(r) {
			t.Errorf("%q should not be a valid reference", r)
		}
	}
}

func TestMemRoundTrip(t *testing.T) {
	ctx := context.Background()
	m := NewMem()
	if err := m.Set(ctx, "db_password", "hunter2"); err != nil {
		t.Fatal(err)
	}
	got, err := m.Get(ctx, "db_password")
	if err != nil || got != "hunter2" {
		t.Fatalf("want hunter2, got %q err %v", got, err)
	}
	if _, err := m.Get(ctx, "absent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if err := m.Delete(ctx, "absent"); err != nil {
		t.Fatalf("deleting an absent reference must not fail: %v", err)
	}
}

func TestMemRejectsBadRef(t *testing.T) {
	if err := NewMem().Set(context.Background(), "BAD REF", "x"); err == nil {
		t.Fatal("a bad reference must be refused")
	}
}

// TestChainOrderWins is the property that makes continuous integration work:
// a value in the environment must beat the value in the file.
func TestChainOrderWins(t *testing.T) {
	ctx := context.Background()
	env := &roStore{name: "env", up: true, values: map[string]string{"db_password": "from-ci"}}
	file := NewMem()
	if err := file.Set(ctx, "db_password", "from-file"); err != nil {
		t.Fatal(err)
	}
	if err := file.Set(ctx, "only_file", "file-only"); err != nil {
		t.Fatal(err)
	}

	c := NewChain(env, file)
	got, err := c.Get(ctx, "db_password")
	if err != nil || got != "from-ci" {
		t.Fatalf("the first backend must win: got %q err %v", got, err)
	}
	got, err = c.Get(ctx, "only_file")
	if err != nil || got != "file-only" {
		t.Fatalf("the chain must read through: got %q err %v", got, err)
	}
}

func TestChainSkipsUnavailable(t *testing.T) {
	env := &roStore{name: "env", up: false, values: map[string]string{"a": "1"}}
	c := NewChain(env, NewMem())
	if c.Name() != "memory" {
		t.Fatalf("an unavailable backend must be dropped, got chain %q", c.Name())
	}
}

// TestChainWriteSkipsReadOnly proves a write does not stop at envstore.
func TestChainWriteSkipsReadOnly(t *testing.T) {
	ctx := context.Background()
	env := &roStore{name: "env", up: true, values: map[string]string{}}
	file := NewMem()
	c := NewChain(env, file)

	if err := c.Set(ctx, "new_ref", "value"); err != nil {
		t.Fatalf("the write must fall through to the writable backend: %v", err)
	}
	if got, _ := file.Get(ctx, "new_ref"); got != "value" {
		t.Fatalf("the writable backend did not get the value, got %q", got)
	}
}

func TestChainWithNoWritableBackendFails(t *testing.T) {
	env := &roStore{name: "env", up: true, values: map[string]string{}}
	c := NewChain(env)
	if err := c.Set(context.Background(), "a", "b"); err == nil {
		t.Fatal("a chain with no writable backend must refuse a write")
	}
}

func TestChainListIsTheUnion(t *testing.T) {
	ctx := context.Background()
	env := &roStore{name: "env", up: true, values: map[string]string{"a": "1", "b": "2"}}
	file := NewMem()
	_ = file.Set(ctx, "b", "2")
	_ = file.Set(ctx, "c", "3")

	refs, err := NewChain(env, file).List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a", "b", "c"}
	if len(refs) != len(want) {
		t.Fatalf("want %v, got %v", want, refs)
	}
	for i := range want {
		if refs[i] != want[i] {
			t.Fatalf("want %v, got %v", want, refs)
		}
	}
}

// TestChainDeleteReachesEveryBackend guards against a half deleted secret,
// which leaves a stale value behind in one place.
func TestChainDeleteReachesEveryBackend(t *testing.T) {
	ctx := context.Background()
	a, b := NewMem(), NewMem()
	_ = a.Set(ctx, "gone", "1")
	_ = b.Set(ctx, "gone", "1")

	if err := NewChain(a, b).Delete(ctx, "gone"); err != nil {
		t.Fatal(err)
	}
	for i, m := range []*Mem{a, b} {
		if _, err := m.Get(ctx, "gone"); !errors.Is(err, ErrNotFound) {
			t.Errorf("backend %d still holds the value", i)
		}
	}
}

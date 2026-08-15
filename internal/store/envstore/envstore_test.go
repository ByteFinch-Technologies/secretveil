package envstore

import (
	"context"
	"errors"
	"testing"

	"github.com/ByteFinch-Technologies/secretveil/internal/store"
)

func TestVarName(t *testing.T) {
	cases := map[string]string{
		"db_password":           "SV_DB_PASSWORD",
		"jwt-secret":            "SV_JWT_SECRET",
		"app.token":             "SV_APP_TOKEN",
		"database_url_password": "SV_DATABASE_URL_PASSWORD",
	}
	for ref, want := range cases {
		if got := VarName(ref); got != want {
			t.Errorf("%s: want %s, got %s", ref, want, got)
		}
	}
}

func TestGet(t *testing.T) {
	s := NewWith(map[string]string{"SV_DB_PASSWORD": "from-ci", "PATH": "/usr/bin"})
	got, err := s.Get(context.Background(), "db_password")
	if err != nil || got != "from-ci" {
		t.Fatalf("want from-ci, got %q err %v", got, err)
	}
	if _, err := s.Get(context.Background(), "absent"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

// TestEmptyEnvironmentIsNotAvailable stops an empty environment from winning
// the chain and hiding the real store behind it.
func TestEmptyEnvironmentIsNotAvailable(t *testing.T) {
	if NewWith(map[string]string{"PATH": "/usr/bin"}).Available() {
		t.Fatal("an environment with no SV_ variable must report unavailable")
	}
	if !NewWith(map[string]string{"SV_A": "1"}).Available() {
		t.Fatal("an environment with an SV_ variable must report available")
	}
}

func TestWriteIsRefused(t *testing.T) {
	s := NewWith(map[string]string{"SV_A": "1"})
	if err := s.Set(context.Background(), "a", "2"); !errors.Is(err, store.ErrReadOnly) {
		t.Fatalf("want ErrReadOnly, got %v", err)
	}
	if err := s.Delete(context.Background(), "a"); !errors.Is(err, store.ErrReadOnly) {
		t.Fatalf("want ErrReadOnly, got %v", err)
	}
}

func TestListOnlyReadsThePrefix(t *testing.T) {
	s := NewWith(map[string]string{
		"SV_DB_PASSWORD": "x",
		"SV_JWT_SECRET":  "y",
		"PATH":           "/usr/bin",
		"HOME":           "/root",
	})
	refs, err := s.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"db_password", "jwt_secret"}
	if len(refs) != len(want) {
		t.Fatalf("want %v, got %v", want, refs)
	}
	for i := range want {
		if refs[i] != want[i] {
			t.Fatalf("want %v, got %v", want, refs)
		}
	}
}

// TestListRefsAreValid proves a listed reference can be used again.
func TestListRefsAreValid(t *testing.T) {
	s := NewWith(map[string]string{"SV_DB_PASSWORD": "x", "SV_A9": "y"})
	refs, _ := s.List(context.Background())
	for _, r := range refs {
		if !store.ValidRef(r) {
			t.Errorf("List returned an unusable reference: %q", r)
		}
	}
}

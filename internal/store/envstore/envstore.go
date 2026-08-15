// Package envstore reads secret values from the process environment.
//
// A continuous integration job puts each value in a variable, and this backend
// reads it there. The backend is read only, because a value written into the
// environment does not survive the process and a silent loss of a secret is
// worse than a refused write.
//
// The variable name is the reference in upper case with the prefix SV_. The
// reference db_password becomes SV_DB_PASSWORD.
package envstore

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/ByteFinch-Technologies/secretveil/internal/store"
)

// Prefix is the variable name prefix for every value this backend reads.
const Prefix = "SV_"

// Store reads from the process environment.
type Store struct {
	// lookup is the environment reader. A test replaces it.
	lookup func(string) (string, bool)
	// all lists the whole environment. A test replaces it.
	all func() []string
}

// New returns a store that reads the real process environment.
func New() *Store {
	return &Store{lookup: os.LookupEnv, all: os.Environ}
}

// NewWith returns a store that reads a fixed map. It is for tests.
func NewWith(values map[string]string) *Store {
	return &Store{
		lookup: func(k string) (string, bool) { v, ok := values[k]; return v, ok },
		all: func() []string {
			out := make([]string, 0, len(values))
			for k, v := range values {
				out = append(out, k+"="+v)
			}
			return out
		},
	}
}

func (s *Store) Name() string { return "envstore" }

// Available reports whether at least one variable with the prefix is set.
// An empty environment must not win the chain, because then every lookup would
// stop here and report a missing secret.
func (s *Store) Available() bool {
	for _, kv := range s.all() {
		if strings.HasPrefix(kv, Prefix) {
			return true
		}
	}
	return false
}

// VarName returns the environment variable name for a reference.
func VarName(ref string) string {
	up := strings.ToUpper(ref)
	up = strings.Map(func(r rune) rune {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		default:
			return '_'
		}
	}, up)
	return Prefix + up
}

func (s *Store) Get(_ context.Context, ref string) (string, error) {
	v, ok := s.lookup(VarName(ref))
	if !ok {
		return "", fmt.Errorf("%w: %s", store.ErrNotFound, ref)
	}
	return v, nil
}

// Set always fails. See the package comment.
func (s *Store) Set(_ context.Context, ref, _ string) error {
	return fmt.Errorf("%w: set %s with the variable %s instead",
		store.ErrReadOnly, ref, VarName(ref))
}

// Delete always fails in the same way as Set.
func (s *Store) Delete(_ context.Context, ref string) error {
	return fmt.Errorf("%w: unset the variable %s instead", store.ErrReadOnly, VarName(ref))
}

// List returns the reference for every variable that carries the prefix. The
// reference is a lower case reading of the name, so it round trips for a name
// that holds only letters, digits and an underscore.
func (s *Store) List(_ context.Context) ([]string, error) {
	var out []string
	for _, kv := range s.all() {
		name, _, ok := strings.Cut(kv, "=")
		if !ok || !strings.HasPrefix(name, Prefix) {
			continue
		}
		ref := strings.ToLower(strings.TrimPrefix(name, Prefix))
		if ref != "" {
			out = append(out, ref)
		}
	}
	sort.Strings(out)
	return out, nil
}

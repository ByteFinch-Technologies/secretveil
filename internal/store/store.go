// Package store holds the real secret values. Nothing else in the program
// keeps a plaintext value on disk.
//
// A backend must satisfy Store. The program picks a backend at start time with
// Select, because a machine without a keyring must still work. A continuous
// integration container is the common example.
package store

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// ErrNotFound means the reference is not in the store.
var ErrNotFound = errors.New("no such reference")

// ErrReadOnly means the backend can read a value but cannot write one.
var ErrReadOnly = errors.New("this store is read only")

// ErrUnavailable means the backend cannot run on this machine.
var ErrUnavailable = errors.New("this store is not available on this machine")

// Store is one backend that holds secret values.
type Store interface {
	// Get returns the value for a reference. It returns ErrNotFound if the
	// reference is absent.
	Get(ctx context.Context, ref string) (string, error)
	// Set writes a value. It replaces any earlier value.
	Set(ctx context.Context, ref, value string) error
	// List returns every reference in the store, in sorted order.
	List(ctx context.Context) ([]string, error)
	// Delete removes a reference. It is not an error to delete a reference
	// that is absent.
	Delete(ctx context.Context, ref string) error
	// Name returns the short name used in the policy file and in messages.
	Name() string
	// Available reports whether this backend can run on this machine.
	Available() bool
}

// ValidRef reports whether a reference has a safe form. A reference goes into
// a file name, into an environment variable name and into a keyring account
// name, so the program keeps the character set narrow.
func ValidRef(ref string) bool {
	if ref == "" || len(ref) > 200 {
		return false
	}
	for i := 0; i < len(ref); i++ {
		c := ref[i]
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '_' || c == '-' || c == '.'
		if !ok {
			return false
		}
	}
	return true
}

// Mem is an in-memory store. It is for tests and for a dry run. It never
// touches the disk, so a value in it does not survive the process.
type Mem struct {
	mu     sync.RWMutex
	values map[string]string
}

// NewMem returns an empty in-memory store.
func NewMem() *Mem { return &Mem{values: map[string]string{}} }

func (m *Mem) Name() string    { return "memory" }
func (m *Mem) Available() bool { return true }

func (m *Mem) Get(_ context.Context, ref string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.values[ref]
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrNotFound, ref)
	}
	return v, nil
}

func (m *Mem) Set(_ context.Context, ref, value string) error {
	if !ValidRef(ref) {
		return fmt.Errorf("bad reference: %q", ref)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.values[ref] = value
	return nil
}

func (m *Mem) List(_ context.Context) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0, len(m.values))
	for k := range m.values {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

func (m *Mem) Delete(_ context.Context, ref string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.values, ref)
	return nil
}

// Chain reads through several backends and writes to the first one that
// accepts a write. The order matters. Put the backend that must win first.
//
// The common order is envstore then agefile. A continuous integration job sets
// the value in the environment, and that value must beat the file.
type Chain struct {
	members []Store
}

// NewChain returns a chain of the backends that are available. It drops a
// backend that reports Available as false.
func NewChain(members ...Store) *Chain {
	live := make([]Store, 0, len(members))
	for _, m := range members {
		if m != nil && m.Available() {
			live = append(live, m)
		}
	}
	return &Chain{members: live}
}

// Members returns the backends that survived the availability check.
func (c *Chain) Members() []Store { return c.members }

func (c *Chain) Available() bool { return len(c.members) > 0 }

func (c *Chain) Name() string {
	names := make([]string, 0, len(c.members))
	for _, m := range c.members {
		names = append(names, m.Name())
	}
	if len(names) == 0 {
		return "empty chain"
	}
	return strings.Join(names, "+")
}

func (c *Chain) Get(ctx context.Context, ref string) (string, error) {
	var firstErr error
	for _, m := range c.members {
		v, err := m.Get(ctx, ref)
		if err == nil {
			return v, nil
		}
		if !errors.Is(err, ErrNotFound) && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		return "", firstErr
	}
	return "", fmt.Errorf("%w: %s", ErrNotFound, ref)
}

// Set writes to the first backend that is not read only.
func (c *Chain) Set(ctx context.Context, ref, value string) error {
	for _, m := range c.members {
		err := m.Set(ctx, ref, value)
		if errors.Is(err, ErrReadOnly) {
			continue
		}
		return err
	}
	return fmt.Errorf("no writable store in the chain %q", c.Name())
}

func (c *Chain) List(ctx context.Context) ([]string, error) {
	seen := map[string]bool{}
	for _, m := range c.members {
		refs, err := m.List(ctx)
		if err != nil {
			return nil, err
		}
		for _, r := range refs {
			seen[r] = true
		}
	}
	out := make([]string, 0, len(seen))
	for r := range seen {
		out = append(out, r)
	}
	sort.Strings(out)
	return out, nil
}

// Delete removes the reference from every writable backend in the chain. A
// half deleted secret is worse than none, so this does not stop at the first
// backend.
func (c *Chain) Delete(ctx context.Context, ref string) error {
	var firstErr error
	for _, m := range c.members {
		err := m.Delete(ctx, ref)
		if err != nil && !errors.Is(err, ErrReadOnly) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

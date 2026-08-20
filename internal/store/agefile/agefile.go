// Package agefile keeps every secret value in one encrypted file.
//
// The file uses the age format, so the encryption is a reviewed
// implementation and not a new one. The key that opens the file comes from one
// of three places, and the program tries them in this order:
//
//  1. The SECRETVEIL_IDENTITY variable, which holds an age identity. Use this
//     in a continuous integration job.
//  2. The SECRETVEIL_PASSPHRASE variable. Use this on a machine with no
//     keyring, for example a headless Linux box.
//  3. The operating system keyring. This is the normal path on a workstation.
//     The program makes an identity on first use and puts it in the keyring.
//
// The keyring holds the identity only, because the identity is 74 characters
// and fits inside the keyring limit. See the keyring package for why that
// limit matters.
package agefile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"filippo.io/age"

	"github.com/ByteFinch-Technologies/secretveil/internal/store"
	"github.com/ByteFinch-Technologies/secretveil/internal/store/keyring"
)

// EnvIdentity names the variable that holds an age identity.
const EnvIdentity = "SECRETVEIL_IDENTITY"

// EnvPassphrase names the variable that holds a passphrase.
const EnvPassphrase = "SECRETVEIL_PASSPHRASE"

// FileName is the name of the encrypted file inside the .secretveil directory.
const FileName = "secrets.age"

// scryptWorkFactor sets the cost of the passphrase key derivation. Zero keeps
// the age default. A test lowers it, because the default takes about one
// second on purpose.
var scryptWorkFactor = 0

// payload is the plaintext inside the encrypted file.
type payload struct {
	Version int               `json:"version"`
	Secrets map[string]string `json:"secrets"`
}

// source is one way to open the file.
type source struct {
	name      string
	identity  age.Identity
	recipient age.Recipient
}

// Store is the encrypted file backend.
type Store struct {
	path  string
	ring  keyring.Keyring
	entry string

	mu     sync.Mutex
	loaded bool
	values map[string]string
	// used is the source that opened the file. A write uses the same source,
	// so a read and a write never disagree about the key.
	used *source
}

// New returns a store for the file at path. The entry is the keyring entry
// name that holds the identity for this project.
func New(path string, ring keyring.Keyring, entry string) *Store {
	return &Store{path: path, ring: ring, entry: entry}
}

// Default returns a store for the .secretveil directory under root.
func Default(root, entry string) *Store {
	return New(filepath.Join(root, ".secretveil", FileName), keyring.New(), entry)
}

func (s *Store) Name() string { return "agefile" }

// Available reports whether at least one key source can work here.
func (s *Store) Available() bool {
	if os.Getenv(EnvIdentity) != "" || os.Getenv(EnvPassphrase) != "" {
		return true
	}
	return s.ring != nil && s.ring.Available()
}

// Path returns the file path. The init flow needs it for the ignore files.
func (s *Store) Path() string { return s.path }

// sources returns every key source that is present, in priority order. It does
// not create a new identity. Use ensureSource for that.
func (s *Store) sources() ([]*source, error) {
	var out []*source

	if raw := strings.TrimSpace(os.Getenv(EnvIdentity)); raw != "" {
		id, err := age.ParseX25519Identity(raw)
		if err != nil {
			return nil, fmt.Errorf("%s is not a valid age identity: %w", EnvIdentity, err)
		}
		out = append(out, &source{name: EnvIdentity, identity: id, recipient: id.Recipient()})
	}

	if pass := os.Getenv(EnvPassphrase); pass != "" {
		id, err := age.NewScryptIdentity(pass)
		if err != nil {
			return nil, fmt.Errorf("%s is not usable: %w", EnvPassphrase, err)
		}
		rec, err := age.NewScryptRecipient(pass)
		if err != nil {
			return nil, fmt.Errorf("%s is not usable: %w", EnvPassphrase, err)
		}
		if scryptWorkFactor > 0 {
			rec.SetWorkFactor(scryptWorkFactor)
		}
		out = append(out, &source{name: EnvPassphrase, identity: id, recipient: rec})
	}

	if s.ring != nil && s.ring.Available() {
		raw, err := s.ring.Get(s.entry)
		if err == nil {
			id, perr := age.ParseX25519Identity(strings.TrimSpace(raw))
			if perr != nil {
				return nil, fmt.Errorf("the keyring entry %q is not a valid age identity: %w", s.entry, perr)
			}
			out = append(out, &source{name: s.ring.Name(), identity: id, recipient: id.Recipient()})
		} else if !errors.Is(err, keyring.ErrNotFound) {
			return nil, err
		}
	}

	return out, nil
}

// ensureSource returns a source for a write. It makes a new identity in the
// keyring if there is no source yet.
func (s *Store) ensureSource() (*source, error) {
	found, err := s.sources()
	if err != nil {
		return nil, err
	}
	if len(found) > 0 {
		return found[0], nil
	}
	if s.ring == nil || !s.ring.Available() {
		return nil, fmt.Errorf(
			"there is no key for the secret file. Set %s to a passphrase, or use a machine with a keyring",
			EnvPassphrase)
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}
	if err := s.ring.Set(s.entry, id.String()); err != nil {
		return nil, fmt.Errorf("the program could not put the file key in the keyring: %w", err)
	}
	return &source{name: s.ring.Name(), identity: id, recipient: id.Recipient()}, nil
}

// load reads and decrypts the file. It is safe to call more than once.
func (s *Store) load() error {
	if s.loaded {
		return nil
	}
	s.values = map[string]string{}

	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		s.loaded = true
		return nil
	}
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		s.loaded = true
		return nil
	}

	found, err := s.sources()
	if err != nil {
		return err
	}
	if len(found) == 0 {
		return fmt.Errorf(
			"the file %s is encrypted and this machine has no key for it. Set %s or %s",
			s.path, EnvIdentity, EnvPassphrase)
	}

	// age refuses a passphrase identity next to any other identity, so the
	// program tries one source at a time.
	var lastErr error
	for _, src := range found {
		r, derr := age.Decrypt(bytes.NewReader(raw), src.identity)
		if derr != nil {
			lastErr = derr
			continue
		}
		plain, rerr := io.ReadAll(r)
		if rerr != nil {
			lastErr = rerr
			continue
		}
		var p payload
		if jerr := json.Unmarshal(plain, &p); jerr != nil {
			return fmt.Errorf("the secret file decrypted but its contents are damaged: %w", jerr)
		}
		if p.Secrets != nil {
			s.values = p.Secrets
		}
		s.used = src
		s.loaded = true
		return nil
	}
	return fmt.Errorf("no key opened the file %s. The last attempt said: %w", s.path, lastErr)
}

// save encrypts and writes the file. The write is atomic, so a crash never
// leaves a half written store.
func (s *Store) save() error {
	src := s.used
	if src == nil {
		var err error
		src, err = s.ensureSource()
		if err != nil {
			return err
		}
		s.used = src
	}

	plain, err := json.Marshal(payload{Version: 1, Secrets: s.values})
	if err != nil {
		return err
	}

	var sealed bytes.Buffer
	w, err := age.Encrypt(&sealed, src.recipient)
	if err != nil {
		return err
	}
	if _, err := w.Write(plain); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}

	return writeFileAtomic(s.path, sealed.Bytes())
}

// writeFileAtomic replaces a file in one step. A reader sees the old file or
// the new file, and never a half written one. A crash in the middle leaves the
// old file, which still opens.
func writeFileAtomic(path string, body []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".secrets-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return syncDir(dir)
}

// syncDir writes the directory entry of a renamed file to the disk.
//
// os.Rename is atomic against a reader, and it is not durable against a power
// cut. The new name lives in the directory, and the directory itself sits in
// the cache of the operating system until something writes it out. A crash
// straight after a rename can therefore leave the old name, the new name, or
// neither. This store holds the only copy of every secret of the project, so
// the write must survive the crash that the atomic rename already survives.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// withWriteLock runs fn while this process holds the only write lock of the
// store directory, and with a cache that fn must fill again.
//
// Two shells can run "secretveil set" at the same moment. Each command reads
// the whole store, adds one value, and writes the whole store back. Without a
// lock between the two processes the second write replaces the first, and one
// secret is lost with no error, no message and no mark in any file.
//
// The cache goes inside the lock, because a store that loaded before the lock
// holds what the other process has since replaced. The read that fn does is
// then a read of the file as it is now.
func (s *Store) withWriteLock(fn func() error) error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	unlock, err := lockDir(dir)
	if err != nil {
		return err
	}
	defer unlock()

	s.loaded = false
	s.values = nil
	s.used = nil
	return fn()
}

func (s *Store) Get(_ context.Context, ref string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return "", err
	}
	v, ok := s.values[ref]
	if !ok {
		return "", fmt.Errorf("%w: %s", store.ErrNotFound, ref)
	}
	return v, nil
}

func (s *Store) Set(_ context.Context, ref, value string) error {
	if !store.ValidRef(ref) {
		return fmt.Errorf("bad reference: %q", ref)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.withWriteLock(func() error {
		if err := s.load(); err != nil {
			return err
		}
		s.values[ref] = value
		return s.save()
	})
}

// SetMany writes several values in one encryption pass. The init flow uses it,
// because a separate pass for each secret is slow and each pass rewrites the
// whole file.
func (s *Store) SetMany(_ context.Context, values map[string]string) error {
	for ref := range values {
		if !store.ValidRef(ref) {
			return fmt.Errorf("bad reference: %q", ref)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.withWriteLock(func() error {
		if err := s.load(); err != nil {
			return err
		}
		for ref, v := range values {
			s.values[ref] = v
		}
		return s.save()
	})
}

func (s *Store) List(_ context.Context) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(s.values))
	for k := range s.values {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

func (s *Store) Delete(_ context.Context, ref string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.withWriteLock(func() error {
		if err := s.load(); err != nil {
			return err
		}
		if _, ok := s.values[ref]; !ok {
			return nil
		}
		delete(s.values, ref)
		return s.save()
	})
}

// Reload drops the cached values, so the next call reads the file again.
func (s *Store) Reload() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loaded = false
	s.values = nil
	s.used = nil
}

// Snapshot returns the encrypted file exactly as it is on disk. It returns nil
// when there is no file yet.
//
// The bytes are still encrypted, so a caller can hold them and write them to a
// log without a leak. The migration uses this to undo a write.
func (s *Store) Snapshot() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// RestoreSnapshot puts the file back the way Snapshot found it. A nil snapshot
// means there was no file, so the file is removed.
func (s *Store) RestoreSnapshot(snap []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// withWriteLock drops the cache, which holds values that the snapshot
	// does not.
	return s.withWriteLock(func() error {
		if snap == nil {
			err := os.Remove(s.path)
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		return writeFileAtomic(s.path, snap)
	})
}

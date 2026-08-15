// Package project finds the root of a project and the places secretveil keeps
// its files.
package project

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Dir is the directory that holds the encrypted file. It sits in the project,
// not in the home directory, because a reference such as api_key means one
// thing in one project and another thing in the next.
const Dir = ".secretveil"

// marker names a file or a directory that shows the top of a project.
var marker = []string{Dir, ".git", "package.json", "go.mod", "pyproject.toml", "Cargo.toml"}

// FindRoot walks up from a directory and returns the top of the project.
//
// It returns the starting directory when it finds no marker, because a small
// project with only a .env file is still a project.
func FindRoot(start string) (string, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	first := dir
	for {
		for _, m := range marker {
			if _, err := os.Stat(filepath.Join(dir, m)); err == nil {
				return dir, nil
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return first, nil
		}
		dir = parent
	}
}

// KeyRefFile holds the name of the keyring entry for this project.
const KeyRefFile = "keyref"

// KeyEntry returns the name of the keyring entry that holds the file key for a
// project.
//
// The name comes from a small file in the project, so the project keeps its
// key after the developer moves or renames the directory. The name is not a
// secret. It is a label, and the key behind it stays in the keyring.
//
// When the file is absent, the name comes from a hash of the path. The hash
// hides the path, because any program on the machine can list the entry names
// in the keychain, and the path of a project can name a client.
func KeyEntry(root string) string {
	body, err := os.ReadFile(filepath.Join(root, Dir, KeyRefFile))
	if err == nil {
		if name := strings.TrimSpace(string(body)); validEntry(name) {
			return name
		}
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		abs = root
	}
	sum := sha256.Sum256([]byte(abs))
	return "filekey-" + hex.EncodeToString(sum[:6])
}

// NewKeyEntry returns a fresh entry name.
func NewKeyEntry() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "filekey-" + hex.EncodeToString(b[:]), nil
}

// WriteKeyEntry records the entry name in the project.
func WriteKeyEntry(root, entry string) error {
	if !validEntry(entry) {
		return errors.New("the keyring entry name is not valid")
	}
	dir := filepath.Join(root, Dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, KeyRefFile), []byte(entry+"\n"), 0o600)
}

// validEntry keeps a hand edited file from reaching the keyring command with
// a name that holds a space or a control character.
func validEntry(name string) bool {
	if len(name) == 0 || len(name) > 64 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
		if !ok {
			return false
		}
	}
	return true
}

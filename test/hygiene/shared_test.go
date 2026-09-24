package hygiene_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/ByteFinch-Technologies/secretveil/internal/fixture"
	"github.com/ByteFinch-Technologies/secretveil/internal/shape"
)

// A value that stands in for a secret must belong to one package.
//
// One invented value once stood in for a secret in 13 files across the whole
// suite. A test that hides value A and then looks for value A passes also when
// the code hides every string of that shape, so the shared value could not
// show that a filter matched the value the store holds. Each test now takes
// its own value from internal/fixture, and this test keeps a shared literal
// from coming back.
func TestNoSecretValueIsSharedAcrossPackages(t *testing.T) {
	root := filepath.Join("..", "..")
	files := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "dist":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(rel)] = string(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 40 {
		t.Fatalf("only %d Go files were read, so this test proves nothing. Check the walk.", len(files))
	}

	for v, pkgs := range sharedValues(files) {
		if _, ok := notASecret[v]; ok {
			continue
		}
		t.Errorf("the value %s is written in %d packages: %s.\n"+
			"Take a value for each test from internal/fixture.",
			v, len(pkgs), strings.Join(pkgs, ", "))
	}
}

// notASecret holds each value that looks random, that more than one package
// writes, and that stands for no secret. Each row says what the value is. A
// row that names a credential is wrong: take the value from internal/fixture.
var notASecret = map[string]string{
	"d41d8cd98f00b204e9800998ecf8427e":                                 "the MD5 of an empty file, a checksum that must not be veiled",
	"1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b":                         "a Git commit hash example that must not be veiled",
	"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/": "the base64 alphabet",
	"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ":   "the alphabet of letters and digits",
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789":   "the alphabet of letters and digits",
	"SECRETVEIL_PASSPHRASE":                                            "the name of an environment variable",
}

// TestTheSharedValueCheckFindsOne is the negative control. It builds files in
// memory, so it writes no shared literal either.
func TestTheSharedValueCheckFindsOne(t *testing.T) {
	v := fixture.Value(t, "shared")
	files := map[string]string{
		"internal/a/a_test.go": "const key = \"API_KEY=" + v + "\"\n",
		"internal/b/b_test.go": "var m = map[string]string{\"api_key\": \"" + v + "\"}\n",
		"internal/b/c_test.go": "const other = \"" + fixture.Value(t, "own") + "\"\n",
		"internal/c/c_test.go": "const own = \"" + fixture.Value(t, "own") + "\"\n",
		"internal/d/d_test.go": "const own = \"" + fixture.Value(t, "one package") + "\"\n",
		"internal/d/e_test.go": "const own = \"" + fixture.Value(t, "one package") + "\"\n",
	}
	got := sharedValues(files)

	if pkgs := got[v]; strings.Join(pkgs, ",") != "internal/a,internal/b" {
		t.Errorf("the value in two packages was not found, got %v", got)
	}
	if pkgs := got[fixture.Value(t, "own")]; len(pkgs) != 2 {
		t.Errorf("a value in a second package was not found, got %v", got)
	}
	if _, ok := got[fixture.Value(t, "one package")]; ok {
		t.Errorf("a value in two files of one package was reported, got %v", got)
	}
}

// sharedValues returns each random-looking value that the files of more than
// one package hold, with the packages that hold it. The key is the path of a
// file, and its directory is the package.
func sharedValues(files map[string]string) map[string][]string {
	where := map[string]map[string]bool{}
	for path, body := range files {
		pkg := filepath.ToSlash(filepath.Dir(path))
		for _, run := range candidates(body) {
			// A run holds "API_KEY=value" as one piece, because a credential
			// can hold "=". The value on its own is what two packages share.
			for _, part := range strings.FieldsFunc(run, func(r rune) bool { return r == '=' || r == ':' }) {
				if !shape.LooksRandom(part) {
					continue
				}
				if where[part] == nil {
					where[part] = map[string]bool{}
				}
				where[part][pkg] = true
			}
		}
	}

	out := map[string][]string{}
	for v, pkgs := range where {
		if len(pkgs) < 2 {
			continue
		}
		list := make([]string, 0, len(pkgs))
		for p := range pkgs {
			list = append(list, p)
		}
		sort.Strings(list)
		out[v] = list
	}
	return out
}

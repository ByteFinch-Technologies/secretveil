// Package runtime starts the child program.
//
// It does three things, and nothing else:
//
//   - It reads the .env files, replaces each sv:// handle with the real value
//     from the store, and puts the result in the child environment.
//   - It starts the child on a pseudo terminal, so a program that asks a
//     question still behaves like a program in a terminal.
//   - It passes every byte of the child output through the filter, so a secret
//     that the child prints does not reach the screen or the log.
//
// The child never learns that secretveil is in the middle. It reads its
// variables from the environment, which is what every framework already does.
package runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ByteFinch-Technologies/secretveil/internal/envfile"
	"github.com/ByteFinch-Technologies/secretveil/internal/handle"
	"github.com/ByteFinch-Technologies/secretveil/internal/store"
)

// DefaultFiles names the files that Resolve reads when the caller gives no
// list. The order is the load order. A later file wins over an earlier one.
//
// The list holds only the two names that mean the same thing in every
// framework. A name such as .env.production means one thing in Next.js and
// another thing in Vite, so the caller must ask for it.
var DefaultFiles = []string{".env", ".env.local"}

// Resolution is the outcome of a resolve pass.
type Resolution struct {
	// Env holds the KEY=value entries for the child. It is the parent
	// environment with the resolved variables added to it.
	Env []string
	// Values maps each reference to the secret behind it. The filter uses it
	// to build the needle list.
	Values map[string]string
	// Missing names each reference that no store holds. The caller stops on a
	// missing reference, because a program that starts without a credential
	// fails later and in a way that is harder to read.
	Missing []string
	// Skipped names each variable that the parent environment already holds.
	// The parent value stays, which is what dotenv, Vite and Next.js all do.
	Skipped []string
	// Files names each file that was read, in the order it was read.
	Files []string
	// Handles counts the handles that were replaced.
	Handles int
}

// Options controls a resolve pass.
type Options struct {
	// Dir is the directory that holds the .env files. An empty value means
	// the working directory.
	Dir string
	// Files names the files to read, relative to Dir. An empty list means
	// DefaultFiles.
	Files []string
	// Parent is the environment to start from. A nil value means os.Environ.
	Parent []string
}

// Resolve reads the .env files and builds the child environment.
//
// A file that does not exist is not an error. A repository often holds only
// .env, and .env.local belongs to one developer.
func Resolve(ctx context.Context, st store.Store, opt Options) (*Resolution, error) {
	dir := opt.Dir
	if dir == "" {
		dir = "."
	}
	names := opt.Files
	if len(names) == 0 {
		names = DefaultFiles
	}
	parent := opt.Parent
	if parent == nil {
		parent = os.Environ()
	}

	held := map[string]bool{}
	for _, e := range parent {
		if k, _, ok := strings.Cut(e, "="); ok {
			held[k] = true
		}
	}

	res := &Resolution{Values: map[string]string{}}
	// cache keeps one store read per reference, even when three files use the
	// same handle.
	cache := map[string]string{}
	gone := map[string]bool{}
	// order keeps the last assignment of each key, and keeps the keys in the
	// order they first appeared.
	order := []string{}
	final := map[string]string{}
	skipped := map[string]bool{}

	for _, name := range names {
		path := filepath.Join(dir, name)
		src, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		res.Files = append(res.Files, path)

		for _, line := range envfile.Parse(src).Assignments() {
			if held[line.Key] {
				// The environment wins. Every framework behaves this way, so a
				// change here would surprise the developer.
				skipped[mark(&res.Skipped, skipped, line.Key)] = true
				continue
			}
			value := line.Value
			if handle.Contains(value) {
				out, missing := handle.Resolve(value, func(ref string) (string, bool) {
					if gone[ref] {
						return "", false
					}
					v, ok := cache[ref]
					if !ok {
						got, err := st.Get(ctx, ref)
						if err != nil {
							gone[ref] = true
							return "", false
						}
						v = got
						cache[ref] = v
						res.Values[ref] = v
					}
					res.Handles++
					return v, true
				})
				for _, ref := range missing {
					addOnce(&res.Missing, ref)
				}
				value = out
			}
			if _, seen := final[line.Key]; !seen {
				order = append(order, line.Key)
			}
			final[line.Key] = value
		}
	}

	res.Env = append(res.Env, parent...)
	for _, k := range order {
		res.Env = append(res.Env, k+"="+final[k])
	}
	sort.Strings(res.Missing)
	sort.Strings(res.Skipped)
	return res, nil
}

// mark adds a key to a list once and returns the key.
func mark(list *[]string, seen map[string]bool, key string) string {
	if !seen[key] {
		*list = append(*list, key)
	}
	return key
}

// addOnce adds a value to a list if the list does not hold it yet.
func addOnce(list *[]string, v string) {
	for _, x := range *list {
		if x == v {
			return
		}
	}
	*list = append(*list, v)
}

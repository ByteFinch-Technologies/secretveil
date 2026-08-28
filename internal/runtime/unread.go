package runtime

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ByteFinch-Technologies/secretveil/internal/handle"
	"github.com/ByteFinch-Technologies/secretveil/internal/migrate"
)

// Unread reports the .env files that hold a handle but that "run" does not read
// on its own.
//
// The default load order is two names, and init rewrites every .env file it
// finds. A project that keeps a value in .env.development therefore ends with a
// handle in a file that run walks past. The framework reads that file itself,
// finds the text "sv://stripe_dev_key", and hands it to the program as if it
// were the key. Nothing leaks, but the program fails and the reason is not on
// the screen.
//
// The default stays two names on purpose. A name such as .env.production means
// one thing in Next.js and another thing in Vite, and a tool that guesses which
// one a project wants is worse than a tool that says what it did not read. So
// the fault is not the default. The fault is silence about it, and this
// function exists to end that silence.
//
// bun makes this common, because bun is a runtime and not a framework and it
// loads the files by itself. bun reads .env, then .env.production or
// .env.development or .env.test by NODE_ENV, then .env.local, then the .local
// name that matches NODE_ENV. That is up to eight names against the two that
// run reads.
//
// Paths come back relative to root, in load order.
func Unread(root string) ([]string, error) {
	paths, err := migrate.Discover(root)
	if err != nil {
		return nil, err
	}
	byDefault := map[string]bool{}
	for _, name := range DefaultFiles {
		byDefault[name] = true
	}

	var out []string
	for _, path := range paths {
		src, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if len(handle.Refs(string(src))) == 0 {
			// A file with no handle in it has nothing for run to resolve, so
			// run never had to read it.
			continue
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			continue
		}
		rel = filepath.ToSlash(rel)
		if byDefault[rel] {
			continue
		}
		out = append(out, rel)
	}
	sort.Strings(out)
	return out, nil
}

// UnreadInRoot is Unread for the root directory only, against the files that
// were read.
//
// run wraps every command a developer types, so it may not walk the tree.
// Unread calls migrate.Discover, which does walk, and that cost is right for
// init and for doctor and wrong here. This function reads one directory and
// then reads only the .env files in it that run did not load.
//
// The read list holds the base name of every file run loaded. A developer who
// already named a file with --env-file must not be told about it again.
//
// The result is the same as Unread for the case that matters. A framework and
// a runtime both read the .env files beside package.json, which is the root.
// A handle in a .env file deeper in the tree is still reported by doctor.
//
// An error is never returned. run must start the command the developer asked
// for, so a directory this function cannot read makes it say nothing.
//
// Names come back relative to root, sorted.
func UnreadInRoot(root string, read []string) []string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	wasRead := map[string]bool{}
	for _, name := range read {
		wasRead[name] = true
	}

	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || wasRead[name] || !migrate.IsSecretFile(name) {
			continue
		}
		if e.Type()&os.ModeSymlink != 0 {
			// A symbolic link inside the project can point at any file on the
			// machine, so it is never followed and never read. The migration
			// makes the same choice.
			continue
		}
		src, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			continue
		}
		if len(handle.Refs(string(src))) == 0 {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// LoadOrder builds the list of files a developer should pass to run, so that
// every file that holds a handle is read.
//
// The order matters, because a later file wins over an earlier one. ".env"
// goes first and ".env.local" goes last, which is the order every framework
// uses. Everything else sits between them, by name.
//
// The extra list is the output of Unread. A file in it that is already one of
// the two default names is ignored, so the result never names a file twice.
func LoadOrder(root string, extra []string) []string {
	var out []string
	if _, err := os.Stat(filepath.Join(root, ".env")); err == nil {
		out = append(out, ".env")
	}

	middle := make([]string, 0, len(extra))
	for _, name := range extra {
		if name == ".env" || name == ".env.local" {
			continue
		}
		middle = append(middle, name)
	}
	sort.Strings(middle)
	out = append(out, middle...)

	if _, err := os.Stat(filepath.Join(root, ".env.local")); err == nil {
		out = append(out, ".env.local")
	}
	return out
}

// RunLine writes the run command that reads every file in the load order. It is
// printed for the developer to copy, so it holds no secret and no path outside
// the project.
func RunLine(files []string) string {
	var b strings.Builder
	b.WriteString("secretveil run")
	for _, name := range files {
		b.WriteString(" --env-file ")
		b.WriteString(name)
	}
	b.WriteString(" -- <command>")
	return b.String()
}

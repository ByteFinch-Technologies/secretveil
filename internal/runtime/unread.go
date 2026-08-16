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

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEveryCommandIsDocumented fails when a command exists in the program and
// not in the documentation.
//
// A command that nobody can find is a command that nobody uses. This went wrong
// once already: "version" was in the program and in docs/commands.md, and not in
// the table in README.md, and nothing said so. The test is cheap and it holds
// the two files to the program.
//
// "help" is not checked. Cobra adds it to every program and a reader already
// knows it.
func TestEveryCommandIsDocumented(t *testing.T) {
	files := []string{
		filepath.Join("..", "..", "README.md"),
		filepath.Join("..", "..", "docs", "commands.md"),
	}
	text := make(map[string]string, len(files))
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		text[f] = string(b)
	}

	root := newRoot()
	// Cobra adds "completion" while it runs, not while it is built, so the test
	// has to ask for it. Without this line the test would not see the command
	// and would report that the documentation is complete when it is not.
	root.InitDefaultCompletionCmd()

	for _, c := range root.Commands() {
		name := c.Name()
		if name == "help" {
			continue
		}
		for _, f := range files {
			// The name is checked inside a code span, because a bare word
			// matches ordinary prose and would pass on any page.
			if !strings.Contains(text[f], "`"+name) {
				t.Errorf("command %q is not documented in %s", name, f)
			}
		}
	}
}

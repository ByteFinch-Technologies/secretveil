package migrate

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// A .env file that names one key twice is common. A developer adds a value at
// the end of the file and does not see that the key is already there. A loader
// reads the last assignment, so the first one is dead text that still holds a
// live secret.
//
// The rewrite used to address a record by key. Every entry of a repeated key
// then wrote the same last record, so the first record kept its value in the
// clear, the value never reached the store, and no later check looked for it.
// init printed a success and exited 0.

func TestADuplicateKeyLeavesNoValueInTheClear(t *testing.T) {
	const first = "Zx91qLbT4vNs7Kd2FhWm0PjR"
	const last = "Ge72uPdA8wFn3Jm5RcVt6Byq"
	root := project(t, map[string]string{
		".env": "API_KEY=" + first + "\nPORT=3000\nAPI_KEY=" + last + "\n",
	})
	st := newFakeStore()
	res, err := Apply(context.Background(), st, Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}

	// Neither value may survive anywhere in the tree.
	assertNoPlaintext(t, root, first)
	assertNoPlaintext(t, root, last)

	// Both values must be in the store, each under its own name.
	values := map[string]bool{}
	for _, v := range st.values {
		values[v] = true
	}
	if !values[first] || !values[last] {
		t.Fatalf("a value was lost: the store holds %d value(s) under %v", len(st.values), res.Refs)
	}

	// Both records must now be a handle.
	body := read(t, filepath.Join(root, ".env"))
	if n := strings.Count(body, "sv://"); n != 2 {
		t.Fatalf("the file holds %d handle(s), want two:\n%s", n, body)
	}
}

// The loader reads the last assignment. The handle on that record must give
// back the value the program had before the migration, or the migration
// changed what the program does.
func TestADuplicateKeyKeepsTheValueTheLoaderReads(t *testing.T) {
	const first = "Zx91qLbT4vNs7Kd2FhWm0PjR"
	const last = "Ge72uPdA8wFn3Jm5RcVt6Byq"
	root := project(t, map[string]string{
		".env": "API_KEY=" + first + "\nAPI_KEY=" + last + "\n",
	})
	st := newFakeStore()
	if _, err := Apply(context.Background(), st, Options{Root: root}); err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimRight(read(t, filepath.Join(root, ".env")), "\n"), "\n")
	ref := refOnLine(t, lines[len(lines)-1])
	if got := st.values[ref]; got != last {
		t.Fatalf("the last record resolves to %q, want the value the loader read", got)
	}
}

// One name for one value is correct. A key that is written twice with the same
// value is not a collision, and it must not produce a second name.
func TestADuplicateKeyWithOneValueTakesOneName(t *testing.T) {
	const value = "Zx91qLbT4vNs7Kd2FhWm0PjR"
	root := project(t, map[string]string{
		".env": "API_KEY=" + value + "\nAPI_KEY=" + value + "\n",
	})
	st := newFakeStore()
	res, err := Apply(context.Background(), st, Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Refs) != 1 || res.Refs[0] != "api_key" {
		t.Fatalf("the store holds %v, want one name", res.Refs)
	}
	assertNoPlaintext(t, root, value)
	body := read(t, filepath.Join(root, ".env"))
	if n := strings.Count(body, "sv://api_key"); n != 2 {
		t.Fatalf("the file holds %d handle(s), want two:\n%s", n, body)
	}
}

// refOnLine reads the reference out of one rewritten line.
func refOnLine(t *testing.T, line string) string {
	t.Helper()
	i := strings.Index(line, "sv://")
	if i < 0 {
		t.Fatalf("this line holds no handle: %q", line)
	}
	ref := line[i+len("sv://"):]
	if j := strings.IndexAny(ref, " \t\"'#"); j >= 0 {
		ref = ref[:j]
	}
	return ref
}

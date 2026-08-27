package migrate

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// fixture is one project shape that the round trip must survive.
//
// Every value in these files is invented. None of them is a real credential.
var fixture = map[string]map[string]string{
	"a plain node project": {
		".env": `NODE_ENV=development
PORT=3000
API_KEY=sk-live-Q9xR2mVn7pLwT4aZ
DATABASE_URL=postgres://app:s3cr3t-p4ssw0rd-x9@db.internal:5432/app
STRIPE_PUBLISHABLE_KEY=pk_test_51H8vKmLpQrStUvWxYz
`,
	},
	"a project with comments, blank lines and quotes": {
		".env": `# The API layer.

API_KEY="sk-live-Q9xR2mVn7pLwT4aZ"    # rotate this every quarter
export SECRET_TOKEN='tok_9x8Kd2LmNpQrS4tU'

# Nothing below here matters.
DEBUG=true
EMPTY=
SPACED = value with spaces
`,
		".env.local": `API_KEY=sk-live-LOCALvalue123456
`,
	},
	"a monorepo with three services": {
		"services/api/.env":    "DB_PASSWORD=p4ss-api-Xy9Lm2Qr\nPORT=8080\n",
		"services/worker/.env": "DB_PASSWORD=p4ss-worker-Ab7Cd3Ef\nQUEUE=default\n",
		"services/web/.env":    "NEXT_PUBLIC_URL=https://example.com\nSESSION_SECRET=sess-Gh4Ij5Kl6Mn7Op8Q\n",
	},
	"a file that names one key twice": {
		".env": `# The first assignment is dead. A loader reads the last one.
API_KEY=Zx91qLbT4vNs7Kd2FhWm0PjR
DB_PASSWORD=p4ss-Xy9Lm2Qr-Ab7Cd3
API_KEY="Ge72uPdA8wFn3Jm5RcVt6Byq"    # the one that wins
`,
	},
	"a file with windows line endings and no final newline": {
		".env": "API_KEY=sk-live-Q9xR2mVn7pLwT4aZ\r\nPORT=3000\r\nTOKEN=tok_9x8Kd2LmNpQrS4tU",
	},
	"a file with a multi-line value": {
		".env": `PRIVATE_KEY="-----BEGIN PRIVATE KEY-----
this-is-not-a-key-it-is-a-fixture-for-the-restore-test
-----END PRIVATE KEY-----"
PORT=3000
`,
	},
	"a node project with a registry token": {
		".env": "API_KEY=sk-live-Q9xR2mVn7pLwT4aZ\n",
		".npmrc": `registry=https://registry.npmjs.org/
//registry.npmjs.org/:_authToken=npm_A9fK2xQw7ZtR4mVn8sLp3JhG1dYc5B
save-exact=true
`,
		"package.json": "{\n  \"name\": \"app\"\n}\n",
	},
	"a project with two registries and a comment": {
		".env": "API_KEY=sk-live-Q9xR2mVn7pLwT4aZ\n",
		".npmrc": `# The public registry.
//registry.npmjs.org/:_authToken=npm_A9fK2xQw7ZtR4mVn8sLp3JhG1dYc5B

; The private one.
@acme:registry=https://npm.pkg.github.com/
//npm.pkg.github.com/:_authToken=ghp_Zq3Wr8Tv1Nb6Mx4Kd7Ls9Gh2Jc5Pf
`,
	},
	"a workspace whose .npmrc is not at the top": {
		".env":                  "API_KEY=sk-live-Q9xR2mVn7pLwT4aZ\n",
		"packages/api/.npmrc":   "//registry.npmjs.org/:_authToken=npm_A9fK2xQw7ZtR4mVn8sLp3JhG1dYc5B\r\n",
		"packages/web/.npmrc":   "//registry.npmjs.org/:_authToken=npm_Zq3Wr8Tv1Nb6Mx4Kd7Ls9Gh2Jc5Pf",
		"packages/api/index.js": "console.log('hello')\n",
	},
}

// TestInitThenRestoreGivesBackTheSameBytes is a release gate.
//
// The migration is only safe if it can be undone. A developer who tries
// secretveil and does not like it must get the exact file back, and a diff
// must show nothing at all.
func TestInitThenRestoreGivesBackTheSameBytes(t *testing.T) {
	for name, files := range fixture {
		t.Run(name, func(t *testing.T) {
			root := project(t, files)
			before := snapshotTree(t, root)

			st := newFakeStore()
			if _, err := Apply(context.Background(), st, Options{Root: root}); err != nil {
				t.Fatalf("the migration failed: %v", err)
			}

			// The migration must really have changed something, or the test
			// proves nothing.
			mid := snapshotTree(t, root)
			same := 0
			for path, body := range before {
				if mid[path] == body {
					same++
				}
			}
			if same == len(before) {
				t.Fatal("the migration changed nothing, so the round trip proves nothing")
			}

			if _, err := Restore(context.Background(), st, root, false); err != nil {
				t.Fatalf("the restore failed: %v", err)
			}
			after := snapshotTree(t, root)

			for path, want := range before {
				got, ok := after[path]
				if !ok {
					t.Fatalf("%s is gone after the round trip", path)
				}
				if got != want {
					t.Fatalf("%s changed.\nbefore:\n%q\nafter:\n%q", path, want, got)
				}
			}
			for path := range after {
				if _, ok := before[path]; !ok {
					t.Fatalf("the round trip added %s", path)
				}
			}
		})
	}
}

// TestRestoreCountsEveryHandle guards a fault that a byte comparison cannot
// see. The report said zero handles while it restored two of them, because the
// counter read the line after the write instead of before it. A wrong count in
// a report about secrets makes the developer doubt the tool.
func TestRestoreCountsEveryHandle(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want int
	}{
		{"one handle on one line", "API_KEY=sk-live-Q9xR2mVn7pLwT4aZ\n", 1},
		{"two handles in two lines", "API_KEY=sk-live-Q9xR2mVn7pLwT4aZ\nTOKEN=tok_9x8Kd2LmNpQrS4tU\n", 2},
		{"a handle inside a longer value", "DATABASE_URL=postgres://app:s3cr3t-p4ssw0rd-x9@db.internal:5432/app\n", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := project(t, map[string]string{".env": tc.body})
			st := newFakeStore()
			if _, err := Apply(context.Background(), st, Options{Root: root}); err != nil {
				t.Fatal(err)
			}
			res, err := Restore(context.Background(), st, root, false)
			if err != nil {
				t.Fatal(err)
			}
			if res.Handles != tc.want {
				t.Fatalf("the report counts %d handles, want %d", res.Handles, tc.want)
			}
		})
	}
}

func TestRestoreStopsWhenTheStoreIsMissingAValue(t *testing.T) {
	root := project(t, map[string]string{".env": sampleEnv})
	st := newFakeStore()
	if _, err := Apply(context.Background(), st, Options{Root: root}); err != nil {
		t.Fatal(err)
	}
	withHandles := read(t, filepath.Join(root, ".env"))

	// The store loses one value, which is what happens when a developer opens
	// the project on a second machine without the key.
	delete(st.values, "api_key")

	res, err := Restore(context.Background(), st, root, false)
	if err == nil {
		t.Fatal("a restore with a missing value must fail")
	}
	if len(res.Missing) != 1 || res.Missing[0] != "api_key" {
		t.Fatalf("the report names %v", res.Missing)
	}
	if got := read(t, filepath.Join(root, ".env")); got != withHandles {
		t.Fatalf("the file changed even though the restore failed:\n%s", got)
	}
}

func TestARestoreDryRunWritesNothing(t *testing.T) {
	root := project(t, map[string]string{".env": sampleEnv})
	st := newFakeStore()
	if _, err := Apply(context.Background(), st, Options{Root: root}); err != nil {
		t.Fatal(err)
	}
	withHandles := read(t, filepath.Join(root, ".env"))

	res, err := Restore(context.Background(), st, root, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 1 {
		t.Fatalf("the dry run names %v", res.Files)
	}
	if got := read(t, filepath.Join(root, ".env")); got != withHandles {
		t.Fatalf("the dry run changed the file:\n%s", got)
	}
}

func TestRestoreKeepsACommentTheDeveloperWrote(t *testing.T) {
	body := "API_KEY=sk-live-Q9xR2mVn7pLwT4aZ    # rotate this every quarter\n"
	root := project(t, map[string]string{".env": body})
	st := newFakeStore()
	if _, err := Apply(context.Background(), st, Options{Root: root}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read(t, filepath.Join(root, ".env")), "rotate this every quarter") {
		t.Fatal("the migration removed the comment of the developer")
	}
	if _, err := Restore(context.Background(), st, root, false); err != nil {
		t.Fatal(err)
	}
	if got := read(t, filepath.Join(root, ".env")); got != body {
		t.Fatalf("the round trip changed the line:\n%q", got)
	}
}

// snapshotTree returns the content of every ordinary file under root, keyed by
// the path relative to root. It skips the directory secretveil owns.
func snapshotTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".secretveil" {
				return filepath.SkipDir
			}
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		name, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		out[name] = string(body)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestEveryFixtureHasASecret keeps a future edit from turning a fixture into a
// file with nothing to migrate, which would make the round trip pass for the
// wrong reason.
func TestEveryFixtureHasASecret(t *testing.T) {
	names := make([]string, 0, len(fixture))
	for name := range fixture {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		root := project(t, fixture[name])
		plan, err := BuildPlan(root)
		if err != nil {
			t.Fatal(err)
		}
		if plan.Counts.Partial+plan.Counts.Veiled == 0 {
			t.Fatalf("the fixture %q holds nothing to migrate", name)
		}
	}
}

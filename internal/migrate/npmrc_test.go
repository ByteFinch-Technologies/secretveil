package migrate

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

const npmToken = "npm_A9fK2xQw7ZtR4mVn8sLp3JhG1dYc5B"
const otherToken = "ghp_Zq3Wr8Tv1Nb6Mx4Kd7Ls9Gh2Jc5Pf"

// TestTheTokenLeavesTheNpmrcAndTheSettingsStay is the whole point of the
// .npmrc work. The token goes to the store, the marker takes its place, and
// every setting npm needs is still readable.
func TestTheTokenLeavesTheNpmrcAndTheSettingsStay(t *testing.T) {
	root := project(t, map[string]string{
		".env": "API_KEY=sk-live-Q9xR2mVn7pLwT4aZ\n",
		".npmrc": "registry=https://registry.npmjs.org/\n" +
			"//registry.npmjs.org/:_authToken=" + npmToken + "\n" +
			"save-exact=true\n",
	})
	st := newFakeStore()

	if _, err := Apply(context.Background(), st, Options{Root: root}); err != nil {
		t.Fatal(err)
	}
	out := read(t, filepath.Join(root, ".npmrc"))

	if strings.Contains(out, npmToken) {
		t.Fatalf("the token is still in the file:\n%s", out)
	}
	want := "registry=https://registry.npmjs.org/\n" +
		"//registry.npmjs.org/:_authToken=${SV_NPMRC_REGISTRY_NPMJS_ORG_AUTHTOKEN}\n" +
		"save-exact=true\n"
	if out != want {
		t.Fatalf("the file is wrong\n got: %q\nwant: %q", out, want)
	}
	if st.values["npmrc_registry_npmjs_org_authtoken"] != npmToken {
		t.Fatalf("the store does not hold the token: %v", st.values)
	}
}

// TestTheNpmrcGetsNoShapeComment guards a rule that a reader could easily
// break. npm parses this file itself, so a comment this tool invented could
// change what npm reads.
func TestTheNpmrcGetsNoShapeComment(t *testing.T) {
	root := project(t, map[string]string{
		".env":   "API_KEY=sk-live-Q9xR2mVn7pLwT4aZ\n",
		".npmrc": "//registry.npmjs.org/:_authToken=" + npmToken + "\n",
	})
	if _, err := Apply(context.Background(), newFakeStore(), Options{Root: root}); err != nil {
		t.Fatal(err)
	}
	if out := read(t, filepath.Join(root, ".npmrc")); strings.Contains(out, "# sv:") {
		t.Fatalf("a shape comment reached the .npmrc:\n%s", out)
	}
}

// TestASecondMigrationLeavesTheNpmrcAlone proves init is safe to run twice. The
// second run reads a file whose value is already a marker, and a marker must
// never go into the store as if it were the token.
func TestASecondMigrationLeavesTheNpmrcAlone(t *testing.T) {
	root := project(t, map[string]string{
		".env":   "API_KEY=sk-live-Q9xR2mVn7pLwT4aZ\n",
		".npmrc": "//registry.npmjs.org/:_authToken=" + npmToken + "\n",
	})
	st := newFakeStore()
	if _, err := Apply(context.Background(), st, Options{Root: root}); err != nil {
		t.Fatal(err)
	}
	first := read(t, filepath.Join(root, ".npmrc"))

	// The second run has nothing left to do, which Apply reports as an error.
	// The file and the store are what this test is about.
	_, _ = Apply(context.Background(), st, Options{Root: root})

	if second := read(t, filepath.Join(root, ".npmrc")); second != first {
		t.Fatalf("the second run changed the file\n got: %q\nwant: %q", second, first)
	}
	if got := st.values["npmrc_registry_npmjs_org_authtoken"]; got != npmToken {
		t.Fatalf("the second run put %q in the store", got)
	}
}

// TestARenamedNpmrcReferenceKeepsItsPrefix guards a fault the fixtures found.
//
// Two workspaces with the same key and different tokens make a collision, and
// the second one gets a new name. The new name kept the file name but lost the
// npmrc_ prefix, and that prefix is how restore knows a marker is ours. The
// result was a file that npm could not use and that restore walked past.
func TestARenamedNpmrcReferenceKeepsItsPrefix(t *testing.T) {
	root := project(t, map[string]string{
		".env":                "API_KEY=sk-live-Q9xR2mVn7pLwT4aZ\n",
		"packages/api/.npmrc": "//registry.npmjs.org/:_authToken=" + npmToken + "\n",
		"packages/web/.npmrc": "//registry.npmjs.org/:_authToken=" + otherToken + "\n",
	})
	st := newFakeStore()
	res, err := Apply(context.Background(), st, Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Renamed) != 1 {
		t.Fatalf("want one rename, got %v", res.Renamed)
	}
	for _, name := range res.Renamed {
		if !strings.HasPrefix(name, "npmrc_") {
			t.Fatalf("the new name %q lost the npmrc_ prefix", name)
		}
	}
	for _, p := range []string{"packages/api/.npmrc", "packages/web/.npmrc"} {
		out := read(t, filepath.Join(root, p))
		if !strings.Contains(out, "${SV_NPMRC_") {
			t.Fatalf("%s holds no marker of ours:\n%s", p, out)
		}
	}
	if _, err := Restore(context.Background(), st, root, false); err != nil {
		t.Fatal(err)
	}
	if got := read(t, filepath.Join(root, "packages/web/.npmrc")); !strings.Contains(got, otherToken) {
		t.Fatalf("restore did not put the second token back:\n%s", got)
	}
}

// TestAQuotedTokenIsLeftAlone proves the narrow rule. npm and this tool do not
// agree on what a quoted value means, so the line is not rewritten at all. A
// wrong guess here would put the wrong bytes in the store or in the file.
func TestAQuotedTokenIsLeftAlone(t *testing.T) {
	body := "//registry.npmjs.org/:_authToken=\"" + npmToken + "\"\n"
	root := project(t, map[string]string{
		".env":   "API_KEY=sk-live-Q9xR2mVn7pLwT4aZ\n",
		".npmrc": body,
	})
	if _, err := Apply(context.Background(), newFakeStore(), Options{Root: root}); err != nil {
		t.Fatal(err)
	}
	if out := read(t, filepath.Join(root, ".npmrc")); out != body {
		t.Fatalf("the file changed\n got: %q\nwant: %q", out, body)
	}
}

// TestAProjectWithOnlyAnNpmrcStillMigrates proves the .npmrc work does not
// depend on a .env file being there.
func TestAProjectWithOnlyAnNpmrcStillMigrates(t *testing.T) {
	root := project(t, map[string]string{
		".npmrc": "//registry.npmjs.org/:_authToken=" + npmToken + "\n",
	})
	st := newFakeStore()
	if _, err := Apply(context.Background(), st, Options{Root: root}); err != nil {
		t.Fatal(err)
	}
	if st.values["npmrc_registry_npmjs_org_authtoken"] != npmToken {
		t.Fatalf("the store does not hold the token: %v", st.values)
	}
}

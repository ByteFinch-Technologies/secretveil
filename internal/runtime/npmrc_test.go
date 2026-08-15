package runtime

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

const npmToken = "npm_A9fK2xQw7ZtR4mVn8sLp3JhG1dYc5B"

// TestTheNpmrcMarkerBecomesAVariable is the run half of the .npmrc work. npm
// expands the marker itself, so all this program has to do is put the value in
// the child environment under the name the marker holds.
func TestTheNpmrcMarkerBecomesAVariable(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".npmrc", "registry=https://registry.npmjs.org/\n"+
		"//registry.npmjs.org/:_authToken=${SV_NPMRC_REGISTRY_NPMJS_ORG_AUTHTOKEN}\n")
	st := memStore(t, map[string]string{"npmrc_registry_npmjs_org_authtoken": npmToken})

	res, err := Resolve(context.Background(), st, Options{Dir: dir, Parent: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := value(res.Env, "SV_NPMRC_REGISTRY_NPMJS_ORG_AUTHTOKEN"); got != npmToken {
		t.Fatalf("the variable is %q", got)
	}
	// The filter needs the value, or the token reaches the screen the first
	// time npm prints it back.
	if res.Values["npmrc_registry_npmjs_org_authtoken"] != npmToken {
		t.Fatal("the value for the filter is missing")
	}
	if res.Handles != 1 {
		t.Fatalf("the pass replaced %d markers, want 1", res.Handles)
	}
}

// TestAnNpmrcInAWorkspaceIsRead proves the pass covers every .npmrc that init
// rewrote, and not only the one at the top. A workspace whose variable was
// never set would fail at the registry with nothing to point at.
func TestAnNpmrcInAWorkspaceIsRead(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "packages", "api")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, sub, ".npmrc", "//registry.npmjs.org/:_authToken=${SV_NPMRC_REGISTRY_NPMJS_ORG_AUTHTOKEN}\n")
	st := memStore(t, map[string]string{"npmrc_registry_npmjs_org_authtoken": npmToken})

	res, err := Resolve(context.Background(), st, Options{Dir: dir, Parent: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := value(res.Env, "SV_NPMRC_REGISTRY_NPMJS_ORG_AUTHTOKEN"); got != npmToken {
		t.Fatalf("the variable is %q", got)
	}
}

// TestTheEnvironmentBeatsTheNpmrcMarker holds the same rule the .env pass
// holds. A developer who exports the variable by hand keeps their value.
func TestTheEnvironmentBeatsTheNpmrcMarker(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".npmrc", "//registry.npmjs.org/:_authToken=${SV_NPMRC_REGISTRY_NPMJS_ORG_AUTHTOKEN}\n")
	st := memStore(t, map[string]string{"npmrc_registry_npmjs_org_authtoken": npmToken})

	res, err := Resolve(context.Background(), st, Options{
		Dir:    dir,
		Parent: []string{"SV_NPMRC_REGISTRY_NPMJS_ORG_AUTHTOKEN=set-by-hand"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := value(res.Env, "SV_NPMRC_REGISTRY_NPMJS_ORG_AUTHTOKEN"); got != "set-by-hand" {
		t.Fatalf("the parent value was lost, the variable is %q", got)
	}
	if len(res.Skipped) != 1 {
		t.Fatalf("the report does not name the skipped variable: %v", res.Skipped)
	}
}

// TestAMissingNpmrcValueIsReported keeps run from starting a program that
// cannot authenticate. A failure at the registry is much harder to read.
func TestAMissingNpmrcValueIsReported(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".npmrc", "//registry.npmjs.org/:_authToken=${SV_NPMRC_REGISTRY_NPMJS_ORG_AUTHTOKEN}\n")
	st := memStore(t, map[string]string{})

	res, err := Resolve(context.Background(), st, Options{Dir: dir, Parent: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Missing) != 1 || res.Missing[0] != "npmrc_registry_npmjs_org_authtoken" {
		t.Fatalf("the missing reference is not reported: %v", res.Missing)
	}
}

// TestAVariableThatIsNotOursIsLeftAlone proves the pass claims only the names
// it wrote. A project that already writes ${NPM_TOKEN} by hand keeps working
// the way it always did.
func TestAVariableThatIsNotOursIsLeftAlone(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".npmrc", "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n")
	st := memStore(t, map[string]string{})

	res, err := Resolve(context.Background(), st, Options{Dir: dir, Parent: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Missing) != 0 {
		t.Fatalf("the pass claimed a variable that is not ours: %v", res.Missing)
	}
	if len(res.Files) != 0 {
		t.Fatalf("the pass reported a file it had no work in: %v", res.Files)
	}
}

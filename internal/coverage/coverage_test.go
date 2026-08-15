package coverage

import (
	"os"
	"path/filepath"
	"testing"
)

// write puts a file in a directory and makes the parent directories.
func write(t *testing.T, root, name, body string) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func scan(t *testing.T, root string) []Finding {
	t.Helper()
	found, err := Scan(root, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// TestNpmrcTokenIsFound is the case that started this package. The report used
// to say nothing was at risk while this exact file sat beside the .env file.
func TestNpmrcTokenIsFound(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".npmrc", "registry=https://registry.npmjs.org/\n"+
		"//registry.npmjs.org/:_authToken=npm_A9fK2xQw7ZtR4mVn8sLp3JhG1dYc5B\n")

	found := scan(t, root)
	if len(found) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(found), found)
	}
	if found[0].Kind != ".npmrc" {
		t.Errorf("kind = %q, want .npmrc", found[0].Kind)
	}
	if len(found[0].Lines) != 1 || found[0].Lines[0] != 2 {
		t.Errorf("lines = %v, want [2]", found[0].Lines)
	}
}

// TestPlaceholderIsNotAFinding keeps the check quiet on a file that is already
// safe. A rule that cries wolf gets switched off, and then it protects nobody.
func TestPlaceholderIsNotAFinding(t *testing.T) {
	cases := map[string]string{
		"variable":  "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n",
		"bare":      "//registry.npmjs.org/:_authToken=$NPM_TOKEN\n",
		"handle":    "//registry.npmjs.org/:_authToken=sv://npm_token\n",
		"angle":     "//registry.npmjs.org/:_authToken=<your-token-here>\n",
		"changeme":  "//registry.npmjs.org/:_authToken=CHANGEME\n",
		"comment":   "# //registry.npmjs.org/:_authToken=npm_realLookingValue123\n",
		"semicolon": "; //registry.npmjs.org/:_authToken=npm_realLookingValue123\n",
		"registry":  "registry=https://registry.npmjs.org/\nsave-exact=true\n",
		"empty":     "",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			write(t, root, ".npmrc", body)
			if found := scan(t, root); len(found) != 0 {
				t.Errorf("want no finding, got %+v", found)
			}
		})
	}
}

func TestEveryKindFires(t *testing.T) {
	cases := []struct {
		name string
		body string
		kind string
	}{
		{".netrc", "machine api.example.com login bob password s3cr3t-value-x9\n", ".netrc"},
		{".yarnrc.yml", "npmAuthToken: npm_A9fK2xQw7ZtR4mVn8sLp3JhG1dYc5B\n", ".yarnrc.yml"},
		{".pypirc", "[pypi]\nusername = bob\npassword = pypi-AgEIcHlwaS5vcmc\n", ".pypirc"},
		{".pgpass", "db.example.com:5432:app:appuser:s3cr3t-p4ssw0rd\n", ".pgpass"},
		{".git-credentials", "https://bob:ghp_aaaaaaaaaaaaaaaaaaaa@github.com\n", ".git-credentials"},
		{".dockercfg", `{"auths":{"r.io":{"auth":"YWJjOmRlZg=="}}}`, "docker config"},
		{".docker/config.json", `{"auths":{"r.io":{"auth":"YWJjOmRlZg=="}}}`, "docker config"},
		{"credentials", "[default]\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCY\n", "aws credentials"},
		{".envrc", "export STRIPE_SECRET_KEY=sk_live_aaaaaaaaaaaaaaaaaaaaaaaa\n", ".envrc"},
		{"terraform.tfvars", "db_password = \"s3cr3t-p4ssw0rd-x9\"\n", "terraform variables"},
		{"prod.auto.tfvars", "api_token = \"aaaaaaaaaaaaaaaaaaaa\"\n", "terraform variables"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			write(t, root, c.name, c.body)
			found := scan(t, root)
			if len(found) != 1 {
				t.Fatalf("want 1 finding, got %d: %+v", len(found), found)
			}
			if found[0].Kind != c.kind {
				t.Errorf("kind = %q, want %q", found[0].Kind, c.kind)
			}
			if found[0].Advice == "" {
				t.Error("a finding with no advice tells the developer nothing")
			}
		})
	}
}

// TestPlainConfigJSONIsIgnored guards the one name common enough to fire on an
// ordinary project file. Only the one inside .docker is a registry login.
func TestPlainConfigJSONIsIgnored(t *testing.T) {
	root := t.TempDir()
	write(t, root, "config.json", `{"auth":"not-a-docker-login"}`)
	if found := scan(t, root); len(found) != 0 {
		t.Errorf("want no finding for a plain config.json, got %+v", found)
	}
}

func TestSkipDirIsObeyed(t *testing.T) {
	root := t.TempDir()
	write(t, root, "node_modules/pkg/.npmrc",
		"//registry.npmjs.org/:_authToken=npm_A9fK2xQw7ZtR4mVn8sLp3JhG1dYc5B\n")

	skip := func(name string) bool { return name == "node_modules" }
	found, err := Scan(root, skip, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Errorf("want no finding inside a skipped directory, got %+v", found)
	}
}

// TestCoveredLineIsNotReported proves the check goes quiet for a line the
// migration rewrites, so one line is never named by two checks.
func TestCoveredLineIsNotReported(t *testing.T) {
	root := t.TempDir()
	path := write(t, root, ".npmrc",
		"//registry.npmjs.org/:_authToken=npm_A9fK2xQw7ZtR4mVn8sLp3JhG1dYc5B\n")

	covered := func(p string, line int) bool { return p == path && line == 1 }
	found, err := Scan(root, nil, covered)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Errorf("want no finding for a covered line, got %+v", found)
	}
}

// TestUncoveredLineSurvivesACoveredOne is the reason the test is per line. One
// .npmrc can hold a line the migration rewrites and a line it refuses, and the
// second one must still reach the report.
func TestUncoveredLineSurvivesACoveredOne(t *testing.T) {
	root := t.TempDir()
	path := write(t, root, ".npmrc",
		"//a.example.com/:_authToken=npm_A9fK2xQw7ZtR4mVn8sLp3JhG1dYc5B\n"+
			"//b.example.com/:_authToken=npm_Zq3Wr8Tv1Nb6Mx4Kd7Ls9Gh2Jc5Pf\n")

	covered := func(p string, line int) bool { return p == path && line == 1 }
	found, err := Scan(root, nil, covered)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || len(found[0].Lines) != 1 || found[0].Lines[0] != 2 {
		t.Fatalf("want only line 2 reported, got %+v", found)
	}
}

// TestSymlinkIsNotFollowed holds the same rule the migration holds. A file in
// the project must not make the program read a file outside it.
func TestSymlinkIsNotFollowed(t *testing.T) {
	outside := t.TempDir()
	real := write(t, outside, "real",
		"//registry.npmjs.org/:_authToken=npm_A9fK2xQw7ZtR4mVn8sLp3JhG1dYc5B\n")

	root := t.TempDir()
	if err := os.Symlink(real, filepath.Join(root, ".npmrc")); err != nil {
		t.Skipf("this machine cannot make a symbolic link: %v", err)
	}
	if found := scan(t, root); len(found) != 0 {
		t.Errorf("want no finding for a symbolic link, got %+v", found)
	}
}

func TestBinaryFileIsIgnored(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".docker/config.json", "\x00\x01\"auth\": \"YWJjOmRlZg==\"")
	if found := scan(t, root); len(found) != 0 {
		t.Errorf("want no finding in a binary file, got %+v", found)
	}
}

func TestNoValueLeaksIntoTheReport(t *testing.T) {
	const token = "npm_A9fK2xQw7ZtR4mVn8sLp3JhG1dYc5B"
	root := t.TempDir()
	write(t, root, ".npmrc", "//registry.npmjs.org/:_authToken="+token+"\n")

	for _, f := range scan(t, root) {
		if f.Advice == token || f.Kind == token {
			t.Fatal("a finding holds the secret value")
		}
	}
}

func TestKindsIsNotEmpty(t *testing.T) {
	if len(Kinds()) == 0 {
		t.Fatal("doctor prints this list to show the limit of the check")
	}
}

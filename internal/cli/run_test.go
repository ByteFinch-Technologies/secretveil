package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestRunWarnsAboutAFileItDidNotRead is the whole reason warnUnread exists.
// init and doctor already said this. run said nothing, and run is where the
// developer stands when the program gets the handle text as its key.
func TestRunWarnsAboutAFileItDidNotRead(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".env", "API_KEY=sv://api_key\n")
	writeFile(t, root, ".env.development", "STRIPE_DEV_KEY=sv://stripe_dev_key\n")

	var out bytes.Buffer
	warnUnread(&out, root, []string{filepath.Join(root, ".env")})

	got := out.String()
	if !strings.Contains(got, ".env.development") {
		t.Errorf("the warning does not name the file:\n%s", got)
	}
	if !strings.Contains(got, "--env-file .env.development") {
		t.Errorf("the copy line does not read the file:\n%s", got)
	}
	if strings.Contains(got, "sv://stripe_dev_key") {
		t.Errorf("the warning printed a handle from the file:\n%s", got)
	}
}

// TestRunSaysNothingOnAnOrdinaryProject keeps the warning rare. A line that
// prints on every run is a line the developer stops reading.
func TestRunSaysNothingOnAnOrdinaryProject(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".env", "API_KEY=sv://api_key\n")
	writeFile(t, root, ".env.local", "OTHER=sv://other\n")

	var out bytes.Buffer
	warnUnread(&out, root, []string{filepath.Join(root, ".env"), filepath.Join(root, ".env.local")})
	if out.Len() != 0 {
		t.Errorf("want no warning, got:\n%s", out.String())
	}
}

// TestTheCopyLineKeepsAFileTheDeveloperNamed guards a warning that takes work
// away. A developer who passed --env-file must not lose that file by running
// the line we print.
func TestTheCopyLineKeepsAFileTheDeveloperNamed(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".env", "API_KEY=sv://api_key\n")
	writeFile(t, root, ".env.production", "PROD=sv://prod\n")
	writeFile(t, root, ".env.development", "DEV=sv://dev\n")

	var out bytes.Buffer
	warnUnread(&out, root, []string{filepath.Join(root, ".env"), filepath.Join(root, ".env.production")})

	got := out.String()
	for _, want := range []string{"--env-file .env.production", "--env-file .env.development"} {
		if !strings.Contains(got, want) {
			t.Errorf("the copy line is missing %q:\n%s", want, got)
		}
	}
}

// TestAnNpmrcIsNotPutInTheLoadOrder guards the copy line. run reports an
// .npmrc among the files it read, and "--env-file .npmrc" would be wrong.
func TestAnNpmrcIsNotPutInTheLoadOrder(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".env", "API_KEY=sv://api_key\n")
	writeFile(t, root, ".env.development", "DEV=sv://dev\n")

	var out bytes.Buffer
	warnUnread(&out, root, []string{filepath.Join(root, ".env"), filepath.Join(root, ".npmrc")})
	if strings.Contains(out.String(), ".npmrc") {
		t.Errorf("an .npmrc reached the load order:\n%s", out.String())
	}
}

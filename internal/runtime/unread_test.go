package runtime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAFileOutsideTheDefaultOrderIsNamed is the whole point of Unread. A
// handle in .env.development is a handle nothing resolves, and the developer
// has to be told which file it is in.
func TestAFileOutsideTheDefaultOrderIsNamed(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".env", "API_KEY=sv://api_key\n")
	write(t, dir, ".env.development", "STRIPE_DEV_KEY=sv://stripe_dev_key\n")

	got, err := Unread(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != ".env.development" {
		t.Fatalf("want [.env.development], got %v", got)
	}
}

// TestTheDefaultFilesAreNeverReported keeps the check quiet on the ordinary
// project. A warning that fires on every project is a warning nobody reads.
func TestTheDefaultFilesAreNeverReported(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".env", "API_KEY=sv://api_key\n")
	write(t, dir, ".env.local", "OTHER=sv://other\n")

	got, err := Unread(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("the default files were reported: %v", got)
	}
}

// TestAFileWithNoHandleIsNotReported proves the test is about work that run
// has to do. A .env.test full of plain settings needs no run at all.
func TestAFileWithNoHandleIsNotReported(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".env", "API_KEY=sv://api_key\n")
	write(t, dir, ".env.test", "NODE_ENV=test\nPORT=3001\n")

	got, err := Unread(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("a file with no handle was reported: %v", got)
	}
}

// TestASampleFileIsNotReported guards the same rule the migration holds. A
// .env.example holds a placeholder, not a value.
func TestASampleFileIsNotReported(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".env", "API_KEY=sv://api_key\n")
	write(t, dir, ".env.example", "API_KEY=sv://api_key\n")

	got, err := Unread(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("a sample file was reported: %v", got)
	}
}

// TestTheLoadOrderPutsLocalLast holds the rule every framework holds. A value
// in .env.local wins, so that file has to be read last.
func TestTheLoadOrderPutsLocalLast(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".env", "A=sv://a\n")
	write(t, dir, ".env.local", "B=sv://b\n")
	write(t, dir, ".env.development", "C=sv://c\n")
	write(t, dir, ".env.staging", "D=sv://d\n")

	extra, err := Unread(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := LoadOrder(dir, extra)
	want := []string{".env", ".env.development", ".env.staging", ".env.local"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("the load order is wrong\n got: %v\nwant: %v", got, want)
	}
}

// TestTheLoadOrderSkipsAFileThatIsNotThere keeps the printed command usable. A
// command that names a file the project does not hold is a command that fails.
func TestTheLoadOrderSkipsAFileThatIsNotThere(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".env.development", "C=sv://c\n")

	extra, err := Unread(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := LoadOrder(dir, extra)
	if len(got) != 1 || got[0] != ".env.development" {
		t.Fatalf("want [.env.development], got %v", got)
	}
}

// TestTheRunLineIsAWholeCommand proves the advice can be copied as it stands.
// A rule the developer has to work out is a rule they get wrong.
func TestTheRunLineIsAWholeCommand(t *testing.T) {
	got := RunLine([]string{".env", ".env.development", ".env.local"})
	want := "secretveil run --env-file .env --env-file .env.development --env-file .env.local -- <command>"
	if got != want {
		t.Fatalf("\n got: %s\nwant: %s", got, want)
	}
}

// TestTheNamedFilesAreActuallyRead closes the loop. The command that Unread and
// LoadOrder build has to resolve the handle they warned about, or the advice is
// wrong.
func TestTheNamedFilesAreActuallyRead(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".env", "API_KEY=sv://api_key\n")
	write(t, dir, ".env.development", "STRIPE_DEV_KEY=sv://stripe_dev_key\n")
	st := memStore(t, map[string]string{
		"api_key":        "sk-live-Q9xR2mVn7pLwT4aZ",
		"stripe_dev_key": "sk-dev-M4nB7vC2xZ9qW5eRt7Y",
	})

	extra, err := Unread(dir)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Resolve(t.Context(), st, Options{
		Dir:    dir,
		Files:  LoadOrder(dir, extra),
		Parent: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := value(res.Env, "STRIPE_DEV_KEY"); got != "sk-dev-M4nB7vC2xZ9qW5eRt7Y" {
		t.Fatalf("the advised command did not resolve the handle, the value is %q", got)
	}
}

// TestTheDefaultOrderLeavesTheHandleUnresolved records the fault this work was
// built for. The default command hands the program the handle text, and that is
// what the doctor check now warns about.
func TestTheDefaultOrderLeavesTheHandleUnresolved(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".env", "API_KEY=sv://api_key\n")
	write(t, dir, ".env.development", "STRIPE_DEV_KEY=sv://stripe_dev_key\n")
	st := memStore(t, map[string]string{
		"api_key":        "sk-live-Q9xR2mVn7pLwT4aZ",
		"stripe_dev_key": "sk-dev-M4nB7vC2xZ9qW5eRt7Y",
	})

	res, err := Resolve(t.Context(), st, Options{Dir: dir, Parent: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := value(res.Env, "STRIPE_DEV_KEY"); ok {
		t.Fatal("the default order read .env.development, so the warning is no longer needed")
	}
}

// TestASymbolicLinkIsNotFollowed holds the rule every scanner in the program
// holds. A link can point anywhere on the machine.
func TestASymbolicLinkIsNotFollowed(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secrets")
	if err := os.WriteFile(outside, []byte("API_KEY=sv://api_key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, ".env.development")); err != nil {
		t.Skipf("this machine does not allow a symbolic link: %v", err)
	}

	got, err := Unread(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range got {
		if name == ".env.development" {
			t.Fatal("the check followed a symbolic link")
		}
	}
}

// TestUnreadInRootNamesTheFileRunMissed is the case that made run print a
// warning. A handle in .env.development reaches the program as text, and run
// is where the developer stands when that happens.
func TestUnreadInRootNamesTheFileRunMissed(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".env", "API_KEY=sv://api_key\n")
	write(t, dir, ".env.development", "STRIPE_DEV_KEY=sv://stripe_dev_key\n")

	got := UnreadInRoot(dir, DefaultFiles)
	if len(got) != 1 || got[0] != ".env.development" {
		t.Fatalf("want [.env.development], got %v", got)
	}
}

// TestUnreadInRootRespectsTheFilesThatWereRead keeps run quiet for a developer
// who already named the file. A warning about work that is done teaches the
// developer to stop reading warnings.
func TestUnreadInRootRespectsTheFilesThatWereRead(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".env", "API_KEY=sv://api_key\n")
	write(t, dir, ".env.development", "STRIPE_DEV_KEY=sv://stripe_dev_key\n")

	got := UnreadInRoot(dir, []string{".env", ".env.development"})
	if len(got) != 0 {
		t.Fatalf("a file that run read was reported: %v", got)
	}
}

// TestUnreadInRootIsQuietOnAnOrdinaryProject holds the warning off the project
// that has nothing wrong with it.
func TestUnreadInRootIsQuietOnAnOrdinaryProject(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".env", "API_KEY=sv://api_key\n")
	write(t, dir, ".env.local", "OTHER=sv://other\n")
	write(t, dir, ".env.test", "PORT=3000\n")
	write(t, dir, ".env.example", "API_KEY=sv://api_key\n")

	if got := UnreadInRoot(dir, DefaultFiles); len(got) != 0 {
		t.Fatalf("want no report, got %v", got)
	}
}

// TestUnreadInRootDoesNotWalk is the constraint that made this function exist
// beside Unread. run wraps every command a developer types, so a handle in a
// subdirectory is doctor's work and not run's.
func TestUnreadInRootDoesNotWalk(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".env", "API_KEY=sv://api_key\n")
	deepDir := filepath.Join(dir, "packages", "api")
	if err := os.MkdirAll(deepDir, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, deepDir, ".env.development", "K=sv://k\n")

	if got := UnreadInRoot(dir, DefaultFiles); len(got) != 0 {
		t.Fatalf("the root check walked into a subdirectory: %v", got)
	}
	deep, err := Unread(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deep) != 1 {
		t.Fatalf("doctor must still find it, got %v", deep)
	}
}

// TestUnreadInRootDoesNotFollowASymbolicLink holds the root check to the same
// promise the migration makes. A link inside the project can point at any file
// on the machine.
func TestUnreadInRootDoesNotFollowASymbolicLink(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secrets")
	if err := os.WriteFile(outside, []byte("API_KEY=sv://api_key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, ".env.development")); err != nil {
		t.Skipf("this machine does not allow a symbolic link: %v", err)
	}

	if got := UnreadInRoot(dir, DefaultFiles); len(got) != 0 {
		t.Fatalf("the check followed a symbolic link: %v", got)
	}
}

// TestUnreadInRootSurvivesAMissingDirectory proves run still starts the
// command. A warning that stops the program is worse than no warning.
func TestUnreadInRootSurvivesAMissingDirectory(t *testing.T) {
	if got := UnreadInRoot(filepath.Join(t.TempDir(), "no-such-dir"), DefaultFiles); got != nil {
		t.Fatalf("want nil, got %v", got)
	}
}

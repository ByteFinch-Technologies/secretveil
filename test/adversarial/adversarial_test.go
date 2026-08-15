// Package adversarial asks one question: can an AI agent get a secret out of
// secretveil?
//
// Every case runs the real binary, in a real project, with the environment of
// an agent. Two of the six cases record something the product does NOT stop.
// They are here on purpose. A limit that is written in a test cannot be quietly
// lost in a later change, and a security tool that hides its limits is worse
// than no tool.
package adversarial

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"filippo.io/age"
)

// The values below are invented. None of them is a real credential.
const (
	apiKey    = "sk-live-Q9xR2mVn7pLwT4aZ"
	jwtSecret = "jw7-Zx9Kq2Lm4Np6Rt8Vw0Yb1Dc3Fg5H"
)

// envBody is the .env file every case starts from.
const envBody = "NODE_ENV=development\n" +
	"PORT=3000\n" +
	"API_KEY=" + apiKey + "\n" +
	"JWT_SECRET=" + jwtSecret + "\n"

// secrets are the values that must never reach the output of an agent.
var secrets = map[string]string{"API_KEY": apiKey, "JWT_SECRET": jwtSecret}

// binary is the compiled secretveil, built once for the whole package.
var binary string

// identity is the age key for the store. It keeps the passphrase path out of
// the test, because that path runs scrypt on purpose and takes about a second
// every time.
var identity string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "secretveil-adversarial-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer os.RemoveAll(dir)

	binary = filepath.Join(dir, "secretveil")
	build := exec.Command("go", "build", "-o", binary, "../../cmd/secretveil")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "the binary did not build:", err)
		os.Exit(1)
	}

	id, err := age.GenerateX25519Identity()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	identity = id.String()

	os.Exit(m.Run())
}

// result is the whole outcome of one command.
type result struct {
	stdout, stderr string
	code           int
}

// all returns everything the command printed, on both streams.
func (r result) all() string { return r.stdout + r.stderr }

// project makes a fresh project with the .env above, already migrated.
func project(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write(t, filepath.Join(root, "package.json"), "{}\n")
	write(t, filepath.Join(root, ".env"), envBody)

	res := sv(t, root, nil, "init", "-y")
	if res.code != 0 {
		t.Fatalf("init failed with code %d:\n%s", res.code, res.all())
	}
	// Every case relies on this. If the migration left a value behind, the
	// case would pass for the wrong reason.
	body := read(t, filepath.Join(root, ".env"))
	for name, v := range secrets {
		if strings.Contains(body, v) {
			t.Fatalf("init left the value of %s in the .env file", name)
		}
	}
	return root
}

// sv runs the binary in a project, as an AI agent unless extra says otherwise.
func sv(t *testing.T, root string, extra []string, args ...string) result {
	t.Helper()
	cmd := exec.Command(binary, args...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"SECRETVEIL_CALLER=agent",
		"SECRETVEIL_IDENTITY="+identity,
		// A marker of the machine that runs the test must not change the
		// answer of the detection rules.
		"CI=",
		"GITHUB_ACTIONS=",
	)
	cmd.Env = append(cmd.Env, extra...)

	var out, errBuf strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	err := cmd.Run()

	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("the command did not run: %v", err)
		}
		code = ee.ExitCode()
	}
	return result{stdout: out.String(), stderr: errBuf.String(), code: code}
}

// mustNotLeak fails when any secret value is anywhere in the output.
func mustNotLeak(t *testing.T, r result, note string) {
	t.Helper()
	for name, v := range secrets {
		if strings.Contains(r.all(), v) {
			t.Errorf("%s: the value of %s reached the output:\n%s", note, name, r.all())
		}
	}
}

// Case 1. The cheapest attack there is.
func TestCase1AnAgentMayNotRunAShell(t *testing.T) {
	root := project(t)
	r := sv(t, root, nil, "run", "--", "bash", "-c", "printenv")

	if r.code == 0 {
		t.Fatalf("the shell ran. It must be refused:\n%s", r.all())
	}
	if !strings.Contains(r.all(), "bash") {
		t.Errorf("the message does not say which program was refused:\n%s", r.all())
	}
	mustNotLeak(t, r, "case 1")
}

// Case 2. The same attack in an interpreter that is not called a shell.
func TestCase2AnAgentMayNotRunInlineCode(t *testing.T) {
	root := project(t)
	for _, args := range [][]string{
		{"node", "-e", "console.log(process.env)"},
		{"node", "--eval=console.log(process.env)"},
		{"python3", "-c", "import os; print(os.environ)"},
		{"/usr/bin/node", "-e", "console.log(process.env)"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			r := sv(t, root, nil, append([]string{"run", "--"}, args...)...)
			if r.code == 0 {
				t.Fatalf("the code ran. It must be refused:\n%s", r.all())
			}
			mustNotLeak(t, r, "case 2")
		})
	}
}

// Case 3. An honest one.
//
// The policy reads the name of a program. It cannot read what the program does.
// A build script is a program with an ordinary name, and the script inside it
// can print the whole environment. So this command is ALLOWED, and the output
// filter is the only thing between the agent and the secret.
//
// This is the case that decides whether the product works. If the filter fails
// here, the second layer is all that is left, and the second layer is a name
// test that anyone can walk around.
func TestCase3AScriptMayRunAndTheFilterIsTheBackstop(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("this case needs a script with a shebang line")
	}
	root := project(t)

	// This stands for "npm run leak", where the leak script is printenv. A
	// script file needs no npm on the machine and makes the same point.
	script := filepath.Join(root, "build.sh")
	write(t, script, "#!/bin/sh\nprintenv\necho \"and again: $API_KEY\"\n")
	if err := os.Chmod(script, 0o755); err != nil {
		t.Fatal(err)
	}

	r := sv(t, root, nil, "run", "-q", "--", "./build.sh")

	if r.code != 0 {
		t.Fatalf("the script was refused, and it should be allowed:\n%s", r.all())
	}
	// It really did dump the environment. Without this the case could pass
	// because nothing ran at all.
	if !strings.Contains(r.all(), "NODE_ENV=development") {
		t.Fatalf("the script did not print the environment, so the case proves nothing:\n%s", r.all())
	}
	// The child really did get the real value, and the filter really did take
	// it out. Without this the case could pass because the child got a handle
	// and there was never a value to leak.
	if !strings.Contains(r.all(), "API_KEY=sv://api_key") {
		t.Fatalf("the filter did not put a handle in place of the value:\n%s", r.all())
	}
	if !strings.Contains(r.all(), "and again: sv://api_key") {
		t.Fatalf("the filter missed the second copy of the value:\n%s", r.all())
	}
	mustNotLeak(t, r, "case 3")
}

// Case 4. A symbolic link must not carry a file from outside into the project.
func TestCase4ASymbolicLinkIsNotFollowed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a symbolic link needs a privilege on windows")
	}
	root := t.TempDir()
	write(t, filepath.Join(root, "package.json"), "{}\n")

	// The target is outside the project, and it holds something private that
	// has nothing to do with this project.
	outside := t.TempDir()
	target := filepath.Join(outside, "private.env")
	const targetBody = "PERSONAL_TOKEN=ghp_Zx9Kq2Lm4Np6Rt8Vw0Yb1Dc3Fg5Hj7K\n"
	write(t, target, targetBody)

	if err := os.Symlink(target, filepath.Join(root, ".env")); err != nil {
		t.Fatal(err)
	}

	r := sv(t, root, nil, "init", "-y")
	if r.code != 0 {
		t.Fatalf("init failed:\n%s", r.all())
	}

	if got := read(t, target); got != targetBody {
		t.Fatalf("init changed the file outside the project:\n%q", got)
	}
	// The link is still a link, so the layout of the developer is unchanged.
	fi, err := os.Lstat(filepath.Join(root, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("init replaced the symbolic link with an ordinary file")
	}
	if !strings.Contains(r.all(), "symbolic link") {
		t.Errorf("init said nothing about the link it skipped:\n%s", r.all())
	}
	mustNotLeak(t, r, "case 4")
}

// Case 5. get is the one command that prints a value, so it needs a human.
func TestCase5RevealNeedsAHumanAndIsRecorded(t *testing.T) {
	root := project(t)

	r := sv(t, root, nil, "get", "api_key", "--reveal")
	if r.code == 0 {
		t.Fatalf("get printed a value to an agent:\n%s", r.all())
	}
	mustNotLeak(t, r, "case 5")

	log := read(t, filepath.Join(root, ".secretveil", "audit.log"))
	if !strings.Contains(log, "\"event\":\"reveal\"") {
		t.Fatalf("the refusal is not in the audit log:\n%s", log)
	}
	if !strings.Contains(log, "refused") {
		t.Fatalf("the audit line does not say it was refused:\n%s", log)
	}
	for name, v := range secrets {
		if strings.Contains(log, v) {
			t.Fatalf("the audit log holds the value of %s", name)
		}
	}
}

// Case 6. The other honest one.
//
// A program that gets a real value can write that value to a file, and then
// anything may read the file. secretveil does not stop this and it cannot. It
// filters the output of a child process. It does not control what a child
// process writes to disk.
//
// This is not a fault to fix later. It is what the product is: the value has to
// reach the program, or the program does not work. The point of the product is
// that the value is not sitting in the .env file where an agent reads it for
// free.
func TestCase6AValueWrittenToAFileIsNotProtected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("this case needs a script with a shebang line")
	}
	root := project(t)

	script := filepath.Join(root, "save.sh")
	write(t, script, "#!/bin/sh\nprintf '%s' \"$API_KEY\" > stolen.txt\n")
	if err := os.Chmod(script, 0o755); err != nil {
		t.Fatal(err)
	}

	r := sv(t, root, nil, "run", "-q", "--", "./save.sh")
	if r.code != 0 {
		t.Fatalf("the script failed:\n%s", r.all())
	}
	// Nothing leaked through the output, which is the part that does work.
	mustNotLeak(t, r, "case 6")

	// And the documented limit holds: the file has the real value in it.
	stolen := read(t, filepath.Join(root, "stolen.txt"))
	if stolen != apiKey {
		t.Fatalf("this case records a known limit of the product, and the limit has changed.\n"+
			"A child process could no longer write a secret to a file.\n"+
			"If that is on purpose, rewrite this case and say so in the threat model.\n"+
			"got %q", stolen)
	}
}

// TestAHumanKeepsEveryPower is the other side of case 1. A tool that refuses
// the developer as well as the agent gets uninstalled.
func TestAHumanKeepsEveryPower(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("this case needs a posix shell")
	}
	root := project(t)

	r := sv(t, root, []string{"SECRETVEIL_CALLER=human"}, "run", "-q", "--", "sh", "-c", "echo hello")
	if r.code != 0 {
		t.Fatalf("a human was refused a shell:\n%s", r.all())
	}
	if !strings.Contains(r.stdout, "hello") {
		t.Fatalf("the command did not run:\n%s", r.all())
	}
}

// TestAPipelineKeepsEveryPower covers the CI reading. A build script is written
// by the team and reviewed, so it keeps its shell. The filter still runs.
func TestAPipelineKeepsEveryPower(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("this case needs a posix shell")
	}
	root := project(t)

	r := sv(t, root, []string{"SECRETVEIL_CALLER=ci"}, "run", "-q", "--", "sh", "-c", "echo $API_KEY")
	if r.code != 0 {
		t.Fatalf("a pipeline was refused a shell:\n%s", r.all())
	}
	mustNotLeak(t, r, "ci")
	if !strings.Contains(r.stdout, "sv://api_key") {
		t.Fatalf("the filter did not replace the value in a pipeline:\n%q", r.stdout)
	}
}

// TestTheDefaultForAnUnknownCallerIsAgent proves the fail-closed rule. A
// command with no terminal and no marker is the shape of a script that nobody
// reviewed.
func TestTheDefaultForAnUnknownCallerIsAgent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("this case needs a posix shell")
	}
	root := project(t)

	r := sv(t, root, []string{"SECRETVEIL_CALLER="}, "run", "--", "sh", "-c", "echo hi")
	if r.code == 0 {
		t.Fatalf("an unknown caller got a shell:\n%s", r.all())
	}
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

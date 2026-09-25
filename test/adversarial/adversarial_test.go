// Package adversarial asks one question: can an AI agent get a secret out of
// secretveil?
//
// Every case runs the real binary, in a real project, with the environment of
// an agent. Two of the seven cases record something the product does NOT stop.
// They are here on purpose. A limit that is written in a test cannot be quietly
// lost in a later change, and a security tool that hides its limits is worse
// than no tool.
//
// Case 7 was added after the other six passed. It found a way out that was
// cheaper than any of them. Six green cases are not proof that the seventh
// does not exist.
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

	"github.com/ByteFinch-Technologies/secretveil/internal/detect"
	"github.com/ByteFinch-Technologies/secretveil/internal/fixture"
)

// secrets are the values that must never reach the output of an agent.
//
// They are invented, and none of them is a real credential. Each case has its
// own values, so a check for a leak looks for the value that this case put in
// the store, and not for a value that every case shares.
func secrets(t testing.TB) map[string]string {
	t.Helper()
	return map[string]string{
		"API_KEY":    fixture.Value(t, "API_KEY"),
		"JWT_SECRET": fixture.Value(t, "JWT_SECRET"),
	}
}

// envBody is the .env file that a case starts from.
func envBody(t testing.TB) string {
	t.Helper()
	v := secrets(t)
	return "NODE_ENV=development\n" +
		"PORT=3000\n" +
		"API_KEY=" + v["API_KEY"] + "\n" +
		"JWT_SECRET=" + v["JWT_SECRET"] + "\n"
}

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
	write(t, filepath.Join(root, ".env"), envBody(t))

	res := sv(t, root, nil, "init", "-y")
	if res.code != 0 {
		t.Fatalf("init failed with code %d:\n%s", res.code, res.all())
	}
	// Every case relies on this. If the migration left a value behind, the
	// case would pass for the wrong reason.
	body := read(t, filepath.Join(root, ".env"))
	for name, v := range secrets(t) {
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
	cmd.Env = append(withoutAgentMarkers(os.Environ()),
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
	for name, v := range secrets(t) {
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

// Case 1b. Another name for the same shell or interpreter (issue 76). The
// default file system of macOS ignores case, so BASH starts /bin/bash, and
// python3.12 is python with a version in its name.
func TestCase1bAnotherNameIsTheSameProgram(t *testing.T) {
	root := project(t)
	for _, args := range [][]string{
		{"BASH", "-c", "echo SHELL_RAN"},
		{"python3.12", "-c", "print('SHELL_RAN')"},
		{"node20", "-e", "console.log('SHELL_RAN')"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			r := sv(t, root, nil, append([]string{"run", "--"}, args...)...)
			if r.code == 0 || strings.Contains(r.all(), "SHELL_RAN") {
				t.Fatalf("the command ran. It must be refused:\n%s", r.all())
			}
			if !strings.Contains(r.stderr, "may not run") {
				t.Errorf("the refusal does not say what was refused:\n%s", r.all())
			}
			mustNotLeak(t, r, "case 1b")
		})
	}
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

// Case 2b. A wrapper in front of a refused program, from issue 55. Each of
// these printed a secret reversed before the fix, and the output filter cannot
// catch a reversed value. The rules have to refuse them.
func TestCase2bAWrapperDoesNotHideTheProgram(t *testing.T) {
	root := project(t)
	backwards := func(s string) string {
		r := []rune(s)
		for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
			r[i], r[j] = r[j], r[i]
		}
		return string(r)
	}
	for _, args := range [][]string{
		{"nice", "sh", "-c", "echo $API_KEY | rev"},
		{"timeout", "5", "sh", "-c", "echo $API_KEY | rev"},
		{"xargs", "sh", "-c", "echo $API_KEY | rev"},
		{"find", ".", "-maxdepth", "0", "-exec", "sh", "-c", "echo $API_KEY | rev", ";"},
		{"git", "-c", "alias.x=!echo $API_KEY | rev", "x"},
		{"awk", `BEGIN{s=ENVIRON["API_KEY"]; for(i=length(s);i>0;i--) printf substr(s,i,1)}`},
		{"jq", "-n", "env"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			r := sv(t, root, nil, append([]string{"run", "--"}, args...)...)
			if r.code == 0 {
				t.Fatalf("the command ran. It must be refused:\n%s", r.all())
			}
			if !strings.Contains(r.stderr, "may not run") {
				t.Errorf("the refusal does not say what was refused:\n%s", r.all())
			}
			mustNotLeak(t, r, "case 2b")
			for name, v := range secrets(t) {
				if strings.Contains(r.all(), backwards(v)) {
					t.Errorf("the value of %s reached the output reversed:\n%s", name, r.all())
				}
			}
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
	for name, v := range secrets(t) {
		if strings.Contains(log, v) {
			t.Fatalf("the audit log holds the value of %s", name)
		}
	}
}

// Case 5b. rm and a replace by set change the store in a way only the
// developer should, from issue 56. A delete loses a secret, and a new value can
// send a program to a host that the agent controls. Neither shows a value, so
// the output filter has nothing to catch.
func TestCase5bAnAgentMayNotRemoveOrReplaceAValue(t *testing.T) {
	root := project(t)
	evil := filepath.Join(t.TempDir(), "value")
	write(t, evil, "postgres://attacker.example/db")

	r := sv(t, root, nil, "rm", "-y", "api_key")
	if r.code == 0 {
		t.Fatalf("an agent removed a value:\n%s", r.all())
	}
	r = sv(t, root, nil, "set", "api_key", "--from-file", evil)
	if r.code == 0 {
		t.Fatalf("an agent replaced a value:\n%s", r.all())
	}
	if !strings.Contains(r.stderr, "human") {
		t.Errorf("the refusal does not say who may do it:\n%s", r.all())
	}

	// The store is as it was.
	r = sv(t, root, []string{"SECRETVEIL_CALLER=human"}, "get", "--reveal", "api_key")
	if r.code != 0 || r.stdout != secrets(t)["API_KEY"] {
		t.Fatalf("the value of api_key changed:\n%s", r.all())
	}

	// A new reference replaces nothing, so an agent may add it.
	r = sv(t, root, nil, "set", "new_ref", "--from-file", evil)
	if r.code != 0 {
		t.Fatalf("an agent could not add a new reference:\n%s", r.all())
	}

	log := read(t, filepath.Join(root, ".secretveil", "audit.log"))
	for _, want := range []string{`"event":"delete"`, `"event":"write"`, "refused", `"detail":"added"`} {
		if !strings.Contains(log, want) {
			t.Errorf("the audit log does not hold %s:\n%s", want, log)
		}
	}
	for _, v := range []string{secrets(t)["API_KEY"], secrets(t)["JWT_SECRET"], "attacker.example"} {
		if strings.Contains(log, v) {
			t.Fatalf("the audit log holds a value:\n%s", log)
		}
	}
}

// TestAHumanMayRemoveAndReplace is the other side of case 5b.
func TestAHumanMayRemoveAndReplace(t *testing.T) {
	root := project(t)
	human := []string{"SECRETVEIL_CALLER=human"}
	next := filepath.Join(t.TempDir(), "value")
	write(t, next, "fake-rotated-Vb8Nq3Xs6Kd1")

	if r := sv(t, root, human, "set", "api_key", "--from-file", next); r.code != 0 {
		t.Fatalf("a human could not replace a value:\n%s", r.all())
	}
	if r := sv(t, root, human, "get", "--reveal", "api_key"); r.stdout != "fake-rotated-Vb8Nq3Xs6Kd1" {
		t.Fatalf("the replace did not take:\n%s", r.all())
	}
	if r := sv(t, root, human, "rm", "-y", "jwt_secret"); r.code != 0 {
		t.Fatalf("a human could not remove a value:\n%s", r.all())
	}
	log := read(t, filepath.Join(root, ".secretveil", "audit.log"))
	if !strings.Contains(log, `"detail":"replaced"`) {
		t.Errorf("the replace is not in the audit log:\n%s", log)
	}
}

// The first set of a new project makes the .secretveil directory. The audit
// record of that write must not be lost because the directory did not exist
// when the command started.
func TestTheFirstSetIsInTheAuditLog(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	value := filepath.Join(t.TempDir(), "value")
	write(t, value, "fake-first-Hs5Tq9Wm2Lc7")

	if r := sv(t, root, nil, "set", "first_key", "--from-file", value); r.code != 0 {
		t.Fatalf("the first set failed:\n%s", r.all())
	}
	log := read(t, filepath.Join(root, ".secretveil", "audit.log"))
	if !strings.Contains(log, `"detail":"added"`) {
		t.Errorf("the first set is not in the audit log:\n%s", log)
	}
	if strings.Contains(log, "fake-first-Hs5Tq9Wm2Lc7") {
		t.Errorf("the audit log holds the value:\n%s", log)
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
	if stolen != secrets(t)["API_KEY"] {
		t.Fatalf("this case records a known limit of the product, and the limit has changed.\n"+
			"A child process could no longer write a secret to a file.\n"+
			"If that is on purpose, rewrite this case and say so in the threat model.\n"+
			"got %q", stolen)
	}
}

// Case 7. The cheapest attack of all, and it worked.
//
// restore is the undo of init. It reads every handle, asks the store for the
// value, and writes the value back into the .env file. Until this case was
// written, an agent could run one command, "secretveil restore", and then read
// the file the way it did before the tool was installed. Every other case in
// this file is harder than that.
//
// The lesson is not about restore. It is that every command which can put a
// value where a file can hold it needs the same gate as "get --reveal". A new
// command has to answer that question before it ships.
func TestCase7AnAgentMayNotUndoTheMigration(t *testing.T) {
	root := project(t)
	env := filepath.Join(root, ".env")
	veiled := read(t, env)

	r := sv(t, root, nil, "restore")
	if r.code == 0 {
		t.Fatalf("an agent restored the plaintext:\n%s", r.all())
	}
	mustNotLeak(t, r, "case 7")

	if got := read(t, env); got != veiled {
		t.Fatalf("the .env file changed. An agent got the plaintext back:\n%s", got)
	}

	log := read(t, filepath.Join(root, ".secretveil", "audit.log"))
	if !strings.Contains(log, `"event":"restore"`) || !strings.Contains(log, "refused") {
		t.Fatalf("the refusal is not in the audit log:\n%s", log)
	}
	for name, v := range secrets(t) {
		if strings.Contains(log, v) {
			t.Fatalf("the audit log holds the value of %s", name)
		}
	}
}

// A dry run stays open to an agent, because it writes nothing. If it ever
// starts to print a value, this case fails.
func TestADryRunOfRestoreTellsAnAgentNothing(t *testing.T) {
	root := project(t)
	veiled := read(t, filepath.Join(root, ".env"))

	r := sv(t, root, nil, "restore", "--dry-run")
	if r.code != 0 {
		t.Fatalf("a dry run was refused:\n%s", r.all())
	}
	mustNotLeak(t, r, "case 7 dry run")
	if got := read(t, filepath.Join(root, ".env")); got != veiled {
		t.Fatalf("a dry run changed the file:\n%s", got)
	}
}

// TestTheCallerIsNamedWithTheRightArticle guards the text of a refusal. The
// messages printed "looks like a agent", because they put "a" in front of the
// bare name.
func TestTheCallerIsNamedWithTheRightArticle(t *testing.T) {
	root := project(t)
	for _, args := range [][]string{
		{"get", "--reveal", "api_key"},
		{"restore"},
		{"doctor"},
		{"rm", "api_key"},
		{"set", "api_key"},
	} {
		r := sv(t, root, nil, args...)
		if !strings.Contains(r.all(), "looks like an agent") {
			t.Errorf("%v does not say \"looks like an agent\":\n%s", args, r.all())
		}
		if strings.Contains(r.all(), "a agent") {
			t.Errorf("%v says \"a agent\":\n%s", args, r.all())
		}
	}
}

// TestAHumanKeepsTheUndo is the other side of case 7. restore is how a
// developer who tries the tool and does not like it gets their project back.
// If it stops working for a human, the product has trapped them.
func TestAHumanKeepsTheUndo(t *testing.T) {
	root := project(t)
	env := filepath.Join(root, ".env")

	r := sv(t, root, []string{"SECRETVEIL_CALLER=human"}, "restore", "--yes")
	if r.code != 0 {
		t.Fatalf("a human could not undo the migration:\n%s", r.all())
	}
	if got := read(t, env); got != envBody(t) {
		t.Fatalf("restore did not give back the original file.\nwant %q\ngot  %q", envBody(t), got)
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

// TestAnAgentCannotCallItselfAHuman covers issue 53. The agent writes the
// command line, so it can put SECRETVEIL_CALLER=human or CI=1 in front of the
// command. The marker of the AI tool must win over both.
func TestAnAgentCannotCallItselfAHuman(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("this case needs a posix shell")
	}
	root := project(t)

	for _, extra := range [][]string{
		{"CLAUDECODE=1", "SECRETVEIL_CALLER=human"},
		{"CLAUDECODE=1", "SECRETVEIL_CALLER=ci"},
		{"CLAUDECODE=1", "CI=1"},
		{"CLAUDECODE=1", "GITHUB_ACTIONS=true"},
	} {
		t.Run(strings.Join(extra, " "), func(t *testing.T) {
			r := sv(t, root, extra, "run", "--", "sh", "-c", "echo $API_KEY | rev")
			if r.code == 0 {
				t.Fatalf("an agent got a shell:\n%s", r.all())
			}
			mustNotLeak(t, r, "agent")
			if strings.Contains(r.all(), reverse(secrets(t)["API_KEY"])) {
				t.Fatalf("the reversed value reached the output:\n%s", r.all())
			}

			r = sv(t, root, extra, "get", "api_key", "--reveal")
			if r.code == 0 {
				t.Fatalf("an agent revealed a value:\n%s", r.all())
			}
			mustNotLeak(t, r, "agent")
		})
	}
}

// TestAnAgentCannotTurnThePolicyOff covers issue 54. The policy file sits in
// the project, where an agent writes. One write of enforce = false gave an
// agent a shell, with no line on the screen and no record in the log.
func TestAnAgentCannotTurnThePolicyOff(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("this case needs a posix shell")
	}
	root := project(t)
	pol := filepath.Join(root, ".secretveil", "policy.toml")
	shell := []string{"run", "-q", "--", "sh", "-c", "echo $API_KEY | rev"}

	for _, body := range []string{"[agent]\nenforce = false\n", "[agent]\ndeny = []\n"} {
		write(t, pol, body)
		r := sv(t, root, nil, shell...)
		if r.code == 0 {
			t.Fatalf("the file %q gave an agent a shell:\n%s", body, r.all())
		}
		if !strings.Contains(r.stderr, "policy approve") {
			t.Fatalf("the refusal does not say why the file did not apply:\n%s", r.all())
		}
		if strings.Contains(r.all(), reverse(secrets(t)["API_KEY"])) {
			t.Fatalf("the reversed value reached the output:\n%s", r.all())
		}
	}

	r := sv(t, root, nil, "policy", "approve")
	if r.code == 0 {
		t.Fatalf("an agent approved its own policy file:\n%s", r.all())
	}

	r = sv(t, root, []string{"SECRETVEIL_CALLER=human"}, "policy", "approve")
	if r.code != 0 {
		t.Fatalf("a human could not approve the file:\n%s", r.all())
	}
	r = sv(t, root, nil, "run", "-q", "--", "sh", "-c", "echo approved")
	if r.code != 0 || !strings.Contains(r.stdout, "approved") {
		t.Fatalf("an approved file did not apply:\n%s", r.all())
	}

	// An agent that edits an approved file cancels the approval.
	write(t, pol, "[agent]\ndeny = []\nallow = []\n")
	r = sv(t, root, nil, shell...)
	if r.code == 0 {
		t.Fatalf("an edit of an approved file kept the approval:\n%s", r.all())
	}

	log := read(t, filepath.Join(root, ".secretveil", "audit.log"))
	if !strings.Contains(log, `"event":"policy"`) || !strings.Contains(log, "no human approved") {
		t.Fatalf("the audit log does not record the approval and the refusal:\n%s", log)
	}
}

func reverse(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

// withoutAgentMarkers removes the markers of the AI tool that runs the tests.
// Without this, a case that sets SECRETVEIL_CALLER=human fails whenever the
// suite runs inside an AI tool, because the marker wins over the override.
func withoutAgentMarkers(env []string) []string {
	out := env[:0:0]
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		if !detect.IsAgentMarker(name) {
			out = append(out, kv)
		}
	}
	return out
}

// TestAStoreFaultIsNamedWithAllowMissing proves issue 38. --allow-missing
// starts the program when the key is wrong, and the developer must see the
// fault, also with -q. Without the line the program starts with no secret
// and the developer looks for the cause in their own code.
func TestAStoreFaultIsNamedWithAllowMissing(t *testing.T) {
	root := project(t)

	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	wrongKey := []string{"SECRETVEIL_IDENTITY=" + other.String()}

	for _, quiet := range []bool{false, true} {
		args := []string{"run", "--allow-missing"}
		if quiet {
			args = append(args, "-q")
		}
		args = append(args, "--", "cat", "package.json")

		r := sv(t, root, wrongKey, args...)
		if r.code != 0 {
			t.Fatalf("quiet=%v: --allow-missing did not start the program, code %d:\n%s", quiet, r.code, r.all())
		}
		if !strings.Contains(r.stderr, "the store could not be read") {
			t.Errorf("quiet=%v: the store fault was not named:\n%s", quiet, r.stderr)
		}
		if strings.Count(r.stderr, "the store could not be read") != 1 {
			t.Errorf("quiet=%v: the fault must be one line:\n%s", quiet, r.stderr)
		}
		mustNotLeak(t, r, "a wrong key")
	}

	// The right key gives no warning. The line is for a fault only.
	r := sv(t, root, nil, "run", "--allow-missing", "--", "cat", "package.json")
	if r.code != 0 {
		t.Fatalf("the right key did not run, code %d:\n%s", r.code, r.all())
	}
	if strings.Contains(r.stderr, "could not be read") {
		t.Errorf("the right key gave a fault warning:\n%s", r.stderr)
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

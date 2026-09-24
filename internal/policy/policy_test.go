package policy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// allowed is a short way to ask the default rules about a command.
func allowed(t *testing.T, args ...string) bool {
	t.Helper()
	return Default().Check(args) == nil
}

func TestTheDefaultRulesRefuseAShell(t *testing.T) {
	for _, args := range [][]string{
		{"bash", "-c", "printenv"},
		{"sh", "-c", "env"},
		{"zsh"},
		{"powershell", "-Command", "ls env:"},
		{"printenv"},
		{"env"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			if allowed(t, args...) {
				t.Errorf("%v was allowed, and it can print the whole environment", args)
			}
		})
	}
}

// TestAPathDoesNotDefeatTheDenyList is the obvious way around a name test.
func TestAPathDoesNotDefeatTheDenyList(t *testing.T) {
	for _, arg := range []string{
		"/bin/bash", "/usr/local/bin/bash", "./bash", "../../bin/bash",
		`C:\Windows\System32\cmd.exe`, "cmd.exe", `C:/Program Files/git/bin/sh.exe`,
	} {
		t.Run(arg, func(t *testing.T) {
			if allowed(t, arg, "-c", "printenv") {
				t.Errorf("%q was allowed, and it is a shell with a path in front of it", arg)
			}
		})
	}
}

func TestInlineCodeFlagsAreRefused(t *testing.T) {
	refused := [][]string{
		{"node", "-e", "console.log(process.env)"},
		{"node", "--eval", "x"},
		{"node", "--eval=x"},
		{"node", "-p", "process.env.API_KEY"},
		{"python3", "-c", "import os"},
		{"ruby", "-e", "puts ENV"},
		{"perl", "-E", "say $ENV{X}"},
		{"php", "-r", "print_r($_ENV);"},
		{"deno", "eval", "x"},
		{"bun", "-e", "x"},
		{"bun", "--eval", "x"},
		{"bun", "-p", "process.env"},
		{"bun", "--print", "process.env"},
		{"bun", "-"},
		{"bun", "run", "-"},
		{"bun", "exec", "echo $API_KEY"},
		{"bun", "repl"},
		{"lua", "-e", "x"},
		{"R", "-e", "x"},
	}
	for _, args := range refused {
		t.Run("refused/"+strings.Join(args, " "), func(t *testing.T) {
			if allowed(t, args...) {
				t.Errorf("%v was allowed, and the flag turns the program into a shell", args)
			}
		})
	}

	// The same programs stay useful when they run a file. A tool that refuses
	// the ordinary case gets turned off.
	permitted := [][]string{
		{"node", "server.js"},
		{"node", "--enable-source-maps", "server.js"},
		{"python3", "manage.py", "runserver"},
		{"ruby", "app.rb"},
		{"deno", "run", "main.ts"},
		{"bun", "run", "dev"},
		{"bun", "server.ts"},
		{"bun", "install"},
		{"bun", "test"},
		{"npm", "run", "dev"},
		{"go", "test", "./..."},
		{"make", "build"},
	}
	for _, args := range permitted {
		t.Run("allowed/"+strings.Join(args, " "), func(t *testing.T) {
			if !allowed(t, args...) {
				t.Errorf("%v was refused, and it is an ordinary command", args)
			}
		})
	}
}

// TestAWrapperDoesNotHideTheProgram covers issue 55. A program that starts
// another program must not undo the rules with one word in front.
func TestAWrapperDoesNotHideTheProgram(t *testing.T) {
	refused := [][]string{
		{"nice", "sh", "-c", "echo $DB_PASS | rev"},
		{"nice", "-n", "10", "bash", "-c", "x"},
		{"nohup", "bash", "-c", "x"},
		{"time", "sh", "-c", "x"},
		{"/usr/bin/time", "-p", "sh", "-c", "x"},
		{"timeout", "5", "sh", "-c", "x"},
		{"stdbuf", "-o0", "sh", "-c", "x"},
		{"setsid", "sh", "-c", "x"},
		{"xargs", "-I{}", "sh", "-c", "x"},
		{"find", ".", "-maxdepth", "0", "-exec", "sh", "-c", "x", ";"},
		{"find", ".", "-execdir", "/bin/sh", "-c", "x", "{}", "+"},
		{"fd", "-x", "sh", "-c", "x"},
		{"command", "printenv"},
		{"caffeinate", "-i", "printenv"},
		{"nice", "node", "-e", "x"},
		{"timeout", "5", "python3", "-c", "x"},
		{"npx", "sh", "-c", "x"},
		{"npm", "exec", "--", "bash", "-c", "x"},
		{"yarn", "dlx", "printenv"},
		// A wrapper inside a wrapper.
		{"nice", "nohup", "timeout", "5", "sh", "-c", "x"},
		{"nice", "timeout", "5", "git", "-c", "alias.x=!sh", "x"},
	}
	for _, args := range refused {
		t.Run("refused/"+strings.Join(args, " "), func(t *testing.T) {
			if allowed(t, args...) {
				t.Errorf("%v was allowed, and the wrapper starts a program the rules refuse", args)
			}
		})
	}

	// A wrapper around an ordinary command stays useful, and a word that is
	// only a value is not read as a program.
	permitted := [][]string{
		{"nice", "npm", "test"},
		{"timeout", "60", "go", "test", "./..."},
		{"nohup", "node", "server.js"},
		{"xargs", "rm"},
		{"find", ".", "-name", "sh"},
		{"find", ".", "-name", "*.log", "-exec", "rm", "{}", ";"},
		{"npm", "install", "--save-dev", "prettier"},
		{"npm", "exec", "prettier", "--", "--check", "."},
		{"npx", "prettier", "--write", "."},
		{"command", "-v", "node"},
	}
	for _, args := range permitted {
		t.Run("allowed/"+strings.Join(args, " "), func(t *testing.T) {
			if !allowed(t, args...) {
				t.Errorf("%v was refused, and it is an ordinary command", args)
			}
		})
	}
}

// TestARefusalThroughAWrapperNamesBoth tells the developer why the rules
// refused a program they did not type first.
func TestARefusalThroughAWrapperNamesBoth(t *testing.T) {
	err := Default().Check([]string{"nice", "-n", "5", "/bin/sh", "-c", "x"})
	var r *Refusal
	if !errors.As(err, &r) {
		t.Fatalf("got %v, want a Refusal", err)
	}
	if r.Program != "sh through nice" {
		t.Errorf("the refusal names %q, want \"sh through nice\"", r.Program)
	}
}

// TestAnAllowListAppliesToTheWrappedProgram stops a wrapper in the allow list
// from carrying in a program that is not.
func TestAnAllowListAppliesToTheWrappedProgram(t *testing.T) {
	p := Default()
	p.Agent.Allow = []string{"nice", "npm"}
	if err := p.Check([]string{"nice", "npm", "test"}); err != nil {
		t.Errorf("nice and npm are both allowed and the command was refused: %v", err)
	}
	if err := p.Check([]string{"nice", "node", "server.js"}); err == nil {
		t.Error("node is not in the allow list and nice carried it in")
	}
}

// TestProgramsThatRunShellText covers the deny names that issue 55 added.
func TestProgramsThatRunShellText(t *testing.T) {
	for _, args := range [][]string{
		{"awk", `BEGIN{print ENVIRON["DB_PASS"]}`},
		{"gawk", "BEGIN{}"},
		{"mawk", "BEGIN{}"},
		{"nawk", "BEGIN{}"},
		{"jq", "-n", "env"},
		{"script", "-q", "/dev/null", "printenv"},
		{"watch", "printenv"},
		{"sudo", "-s"},
		{"su", "-c", "printenv"},
		{"chroot", "/"},
		{"unshare", "-r"},
		{"flock", "/tmp/x", "-c", "printenv"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			if allowed(t, args...) {
				t.Errorf("%v was allowed, and it runs shell text or program text from an argument", args)
			}
		})
	}
}

// TestARunnerDoesNotHideTheProgram covers the tools that start a program for
// a project: a task runner, an environment loader, a terminal multiplexer. Each
// one takes the command as its own arguments, or as one string.
func TestARunnerDoesNotHideTheProgram(t *testing.T) {
	for _, args := range [][]string{
		{"parallel", "printenv", ":::", "a"},
		{"parallel", "printenv {}", ":::", "a"},
		{"tmux", "new", "printenv"},
		{"tmux", "new-session", "-d", "sh -c printenv"},
		{"screen", "-dm", "printenv"},
		{"hyperfine", "printenv"},
		{"cross-env", "A=1", "printenv"},
		{"dotenv", "--", "printenv"},
		{"direnv", "exec", ".", "printenv"},
		{"mise", "exec", "--", "printenv"},
		{"mise", "x", "node@20", "--", "node", "-e", "1"},
		{"uv", "run", "printenv"},
		{"uv", "run", "python", "-c", "1"},
		{"poetry", "run", "printenv"},
		{"pipenv", "run", "printenv"},
		{"pdm", "run", "printenv"},
		{"conda", "run", "-n", "base", "printenv"},
		{"pixi", "run", "printenv"},
		{"rye", "run", "printenv"},
		{"bundle", "exec", "printenv"},
		{"bundle", "exec", "ruby", "-e", "1"},
		{"nice", "tmux", "new", "sh -c printenv"},
	} {
		t.Run("refused/"+strings.Join(args, " "), func(t *testing.T) {
			if allowed(t, args...) {
				t.Errorf("%v was allowed, and the runner starts a program the rules refuse", args)
			}
		})
	}
	for _, args := range [][]string{
		{"uv", "run", "pytest"},
		{"uv", "pip", "install", "env"},
		{"poetry", "install"},
		{"bundle", "install"},
		{"bundle", "exec", "rspec"},
		{"direnv", "allow"},
		{"mise", "install", "node"},
		{"hyperfine", "npm test"},
		{"tmux", "ls"},
	} {
		t.Run("allowed/"+strings.Join(args, " "), func(t *testing.T) {
			if !allowed(t, args...) {
				t.Errorf("%v was refused, and it starts no program the rules refuse", args)
			}
		})
	}
}

// TestGitConfigFromTheCommandLine covers "git -c alias.x=!cmd x", which runs a
// shell. The -c is a global option, and after the subcommand the same letters
// mean something else.
func TestGitConfigFromTheCommandLine(t *testing.T) {
	for _, args := range [][]string{
		{"git", "-c", "alias.x=!echo $DB_PASS | rev", "x"},
		{"git", "-c", "core.pager=sh -c printenv", "log"},
		{"git", "-C", "sub", "-c", "alias.x=!sh", "x"},
		{"git", "--no-pager", "-c", "alias.x=!sh", "x"},
		{"git", "--config-env=alias.x=CMD", "x"},
		{"git", "--config-env", "alias.x=CMD", "x"},
	} {
		t.Run("refused/"+strings.Join(args, " "), func(t *testing.T) {
			if allowed(t, args...) {
				t.Errorf("%v was allowed, and it runs a shell", args)
			}
		})
	}
	for _, args := range [][]string{
		{"git", "status"},
		{"git", "commit", "-c", "HEAD"},
		{"git", "grep", "-c", "TODO"},
		{"git", "-C", "sub", "log", "-c"},
	} {
		t.Run("allowed/"+strings.Join(args, " "), func(t *testing.T) {
			if !allowed(t, args...) {
				t.Errorf("%v was refused, and it runs no shell", args)
			}
		})
	}
}

// TestAFlagAfterTheEndOfFlagsIsAValue guards a wrong refusal. Everything after
// a bare -- belongs to the program, so a script argument that reads -e is not
// an inline code flag.
func TestAFlagAfterTheEndOfFlagsIsAValue(t *testing.T) {
	if !allowed(t, "node", "build.js", "--", "-e", "some value") {
		t.Error("an argument after -- was read as a flag")
	}
}

// TestAProgramWithNoFlagListIsAlwaysRefused covers ssh, which moves data off
// the machine whatever its flags are.
func TestAProgramWithNoFlagListIsAlwaysRefused(t *testing.T) {
	if allowed(t, "ssh", "build@example.com") {
		t.Error("ssh was allowed")
	}
	if allowed(t, "/usr/bin/ssh") {
		t.Error("ssh with a path was allowed")
	}
}

func TestAnAllowListRefusesEverythingElse(t *testing.T) {
	p := Default()
	p.Agent.Allow = []string{"npm", "go"}

	if err := p.Check([]string{"npm", "run", "build"}); err != nil {
		t.Errorf("npm is in the allow list and it was refused: %v", err)
	}
	if err := p.Check([]string{"curl", "https://example.com"}); err == nil {
		t.Error("curl is not in the allow list and it was allowed")
	}
	// The deny list still wins over the allow list.
	p.Agent.Allow = []string{"bash"}
	if err := p.Check([]string{"bash", "-c", "printenv"}); err == nil {
		t.Error("bash was allowed because it was put in the allow list")
	}
}

func TestEnforceFalseTurnsEveryRuleOff(t *testing.T) {
	p := Default()
	p.Agent.Enforce = false
	if err := p.Check([]string{"bash", "-c", "printenv"}); err != nil {
		t.Errorf("the rules are off and a command was still refused: %v", err)
	}
}

func TestAnEmptyCommandIsAllowed(t *testing.T) {
	if err := Default().Check(nil); err != nil {
		t.Errorf("an empty command gave %v", err)
	}
}

// TestARefusalSaysWhatToDo matters more than it looks. A refusal a developer
// cannot act on gets fixed by turning the tool off.
func TestARefusalSaysWhatToDo(t *testing.T) {
	err := Default().Check([]string{"/bin/bash", "-c", "x"})
	var r *Refusal
	if !errors.As(err, &r) {
		t.Fatalf("got %v, want a Refusal", err)
	}
	if r.Program != "bash" {
		t.Errorf("the refusal names %q, want bash", r.Program)
	}
	for _, part := range []string{"bash", "deny list"} {
		if !strings.Contains(err.Error(), part) {
			t.Errorf("the message %q does not hold %q", err.Error(), part)
		}
	}
	if r.Advice == "" {
		t.Error("the refusal gives no advice")
	}
}

func TestLoad(t *testing.T) {
	t.Run("a project with no file gets the default rules", func(t *testing.T) {
		p, err := Load(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if !p.Agent.Enforce {
			t.Error("the rules are off by default, and they should be on")
		}
		if p.Check([]string{"bash", "-c", "x"}) == nil {
			t.Error("the default deny list is missing")
		}
	})

	t.Run("a file that names one setting keeps the rest", func(t *testing.T) {
		root := writePolicy(t, "[agent]\nallow = [\"npm\"]\n")
		p, err := Load(root)
		if err != nil {
			t.Fatal(err)
		}
		if p.Check([]string{"npm", "run", "dev"}) != nil {
			t.Error("npm was refused, and it is in the allow list")
		}
		// The deny list came from the default, not from the file.
		if p.Check([]string{"bash", "-c", "x"}) == nil {
			t.Error("the default deny list was lost")
		}
	})

	t.Run("a file may empty a list on purpose", func(t *testing.T) {
		root := writePolicy(t, "[agent]\ndeny = []\n")
		p, err := Load(root)
		if err != nil {
			t.Fatal(err)
		}
		if p.Check([]string{"bash", "-c", "x"}) != nil {
			t.Error("the deny list is empty in the file and bash was still refused")
		}
	})

	t.Run("a setting nobody knows is an error", func(t *testing.T) {
		root := writePolicy(t, "[agent]\nenfroce = true\n")
		if _, err := Load(root); err == nil {
			t.Fatal("a misspelled setting was accepted, and the rule it meant to set was silently off")
		}
	})

	t.Run("a broken file is an error", func(t *testing.T) {
		root := writePolicy(t, "[agent\nenforce = ")
		if _, err := Load(root); err == nil {
			t.Fatal("a broken file was accepted")
		}
	})
}

// TestTheSampleFileParses guards the file that init writes. A sample that does
// not load would break every project on its first policy edit.
func TestTheSampleFileParses(t *testing.T) {
	root := writePolicy(t, Sample)
	p, err := Load(root)
	if err != nil {
		t.Fatalf("the sample file does not load: %v", err)
	}

	// The sample has to say the same thing as the code, or a developer who
	// reads it gets a surprise.
	d := Default()
	if p.Agent.Enforce != d.Agent.Enforce {
		t.Errorf("the sample sets enforce to %v, and the default is %v", p.Agent.Enforce, d.Agent.Enforce)
	}
	for _, args := range [][]string{
		{"bash", "-c", "x"}, {"printenv"}, {"node", "-e", "x"}, {"ssh", "host"},
		{"nice", "sh", "-c", "x"}, {"jq", "-n", "env"}, {"awk", "BEGIN{}"},
		{"git", "-c", "alias.x=!sh", "x"}, {"npx", "-c", "x"}, {"sudo", "-s"},
		{"git", "commit", "-c", "HEAD"},
	} {
		if (p.Check(args) == nil) != (d.Check(args) == nil) {
			t.Errorf("the sample and the default disagree about %v", args)
		}
	}
}

// TestTheSampleHoldsEveryDefaultRule keeps the two lists in step. A name that
// is added to the default and not to the sample is lost in every project that
// runs init.
func TestTheSampleHoldsEveryDefaultRule(t *testing.T) {
	p, err := Load(writePolicy(t, Sample))
	if err != nil {
		t.Fatal(err)
	}
	d := Default()
	for _, name := range d.Agent.Deny {
		if p.Check([]string{name}) == nil {
			t.Errorf("the sample allows %s, and the default refuses it", name)
		}
	}
	for name, flags := range d.Agent.InlineCode {
		got, ok := p.Agent.InlineCode[name]
		if !ok {
			t.Errorf("the sample has no inline_code rule for %s", name)
			continue
		}
		for _, f := range flags {
			if !contains(got, f) {
				t.Errorf("the sample inline_code rule for %s does not hold %s", name, f)
			}
		}
	}
}

func writePolicy(t *testing.T, body string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, ".secretveil")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

// TestWeakerNamesWhatAFileTurnsOff covers issue 54. The file sits where an
// agent can write, so a file that turns a default rule off must be seen.
func TestWeakerNamesWhatAFileTurnsOff(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string // a piece of one reason, or "" for no reason at all
	}{
		{"the sample file keeps every rule", Sample, ""},
		{"a file that only adds rules is not weaker", "[agent]\ndeny = [" + quoted(Default().Agent.Deny) + ", \"curl\"]\nallow = [\"npm\"]\n", ""},
		{"enforce false", "[agent]\nenforce = false\n", "enforce is false"},
		{"an empty deny list", "[agent]\ndeny = []\n", "the deny list does not hold sh"},
		{"one deny name gone", "[agent]\ndeny = [\"bash\"]\n", "the deny list does not hold zsh"},
		{"an inline flag gone", "[agent.inline_code]\nnode = [\"-e\"]\n", "inline_code for node does not hold --eval"},
		{"ssh allowed with flags", "[agent.inline_code]\nssh = [\"-o\"]\n", "ssh is no longer refused for every use"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := Load(writePolicy(t, c.body))
			if err != nil {
				t.Fatal(err)
			}
			got := Weaker(p)
			if c.want == "" {
				if len(got) != 0 {
					t.Fatalf("want no reason, got %q", got)
				}
				return
			}
			if !strings.Contains(strings.Join(got, "\n"), c.want) {
				t.Fatalf("the reasons %q do not hold %q", got, c.want)
			}
		})
	}
}

// TestAPathInThePolicyNamesTheProgram covers the review of PR 64. A deny list
// of paths looked complete to Weaker and matched nothing in Check, so an agent
// could turn every rule off with no approval.
func TestAPathInThePolicyNamesTheProgram(t *testing.T) {
	var deny []string
	for _, name := range Default().Agent.Deny {
		deny = append(deny, "/bin/"+name)
	}
	body := "[agent]\nenforce = true\ndeny = [" + quoted(deny) + "]\nallow = [\"/usr/bin/npm\", \"sh\", \"node\"]\n" +
		"[agent.inline_code]\nnode = [\"-e\"]\n\"/usr/local/bin/node\" = []\n"
	p, err := Load(writePolicy(t, body))
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"sh", "-c", "x"}, {"printenv"}, {"/usr/bin/printenv"}, {"node", "app.js"}} {
		if p.Check(args) == nil {
			t.Errorf("a policy that names the program by its path allowed %q", args)
		}
	}
	if err := p.Check([]string{"npm", "test"}); err != nil {
		t.Errorf("an allow entry written as a path did not allow npm: %v", err)
	}
	if got := p.Agent.InlineCode["node"]; len(got) != 0 {
		t.Errorf("two keys for node did not join into the stricter rule, got %q", got)
	}
	if _, ok := p.Agent.InlineCode["/usr/local/bin/node"]; ok {
		t.Error("the key written as a path was kept")
	}
}

// TestTheFloorPutsEveryDefaultRuleBack is the rule set an agent gets from a
// file that no human approved.
func TestTheFloorPutsEveryDefaultRuleBack(t *testing.T) {
	p, err := Load(writePolicy(t, "[agent]\nenforce = false\ndeny = [\"curl\"]\nallow = [\"npm\", \"sh\"]\n[agent.inline_code]\nssh = [\"-o\"]\nnode = []\ngo = [\"run\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	f := Floor(p)
	if reasons := Weaker(f); len(reasons) != 0 {
		t.Fatalf("the floor is still weaker than the defaults: %q", reasons)
	}
	for _, args := range [][]string{{"sh", "-c", "x"}, {"curl", "x"}, {"ssh", "host"}, {"node", "app.js"}, {"go", "run", "."}} {
		if f.Check(args) == nil {
			t.Errorf("the floor allowed %q", args)
		}
	}
	if f.Check([]string{"npm", "test"}) != nil {
		t.Error("the floor refused a program that the allow list names")
	}
	if p.Check([]string{"sh", "-c", "x"}) != nil {
		t.Error("Floor changed the policy it was given")
	}
}

func TestLoadWithHash(t *testing.T) {
	root := writePolicy(t, "[agent]\nenforce = true\n")
	_, a, err := LoadWithHash(root)
	if err != nil || len(a) != 64 {
		t.Fatalf("got hash %q err %v", a, err)
	}
	_, b, _ := LoadWithHash(root)
	if a != b {
		t.Fatal("the same file gave two hashes")
	}
	root2 := writePolicy(t, "[agent]\nenforce = true \n")
	if _, c, _ := LoadWithHash(root2); c == a {
		t.Fatal("two different files gave one hash")
	}
	if _, d, err := LoadWithHash(t.TempDir()); err != nil || d != "" {
		t.Fatalf("no file must give no hash, got %q err %v", d, err)
	}
}

func quoted(names []string) string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = `"` + n + `"`
	}
	return strings.Join(out, ", ")
}

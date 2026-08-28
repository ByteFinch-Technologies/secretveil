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
	} {
		if (p.Check(args) == nil) != (d.Check(args) == nil) {
			t.Errorf("the sample and the default disagree about %v", args)
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

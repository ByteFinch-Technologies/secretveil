package policy

import (
	"errors"
	"strings"
	"testing"
)

// refusedAll and allowedAll run a table of commands against the default rules.
func refusedAll(t *testing.T, why string, cmds [][]string) {
	t.Helper()
	for _, args := range cmds {
		t.Run("refused/"+strings.Join(args, " "), func(t *testing.T) {
			if allowed(t, args...) {
				t.Errorf("%v was allowed, and %s", args, why)
			}
		})
	}
}

func allowedAll(t *testing.T, cmds [][]string) {
	t.Helper()
	for _, args := range cmds {
		t.Run("allowed/"+strings.Join(args, " "), func(t *testing.T) {
			if err := Default().Check(args); err != nil {
				t.Errorf("%v was refused, and it is an ordinary command: %v", args, err)
			}
		})
	}
}

// TestAFlagInAClusterIsRefused covers issue 77. An interpreter reads -lne as
// -l, -n and -e, and it reads -cCODE as -c with the value CODE.
func TestAFlagInAClusterIsRefused(t *testing.T) {
	refusedAll(t, "the cluster holds a flag that runs code", [][]string{
		{"perl", "-le", "print 1"},
		{"perl", "-lne", "print"},
		{"perl", "-lane", "print $F[0]", "data.txt"},
		{"perl", "-0777", "-ne", "print"},
		{"perl", "-Mstrict", "-e", "1"},
		{"perl", "-I", "lib", "-e", "1"},
		{"node", "-pe", "process.env"},
		{"node", "--eval=process.env"},
		{"node", "-r", "dotenv/config", "-p", "process.env"},
		{"python3", "-Sc", "import os"},
		{"python3", "-cimport os"},
		{"python3", "-W", "ignore", "-c", "x"},
		{"python3", "-Xdev", "-c", "x"},
		{"python3.12", "-Ic", "x"},
		{"ruby", "-we", "p ENV"},
		{"ruby", "-rjson", "-e", "p ENV"},
		{"php", "-nr", "echo 1;"},
		{"php", "-d", "x=1", "-r", "echo 1;"},
		{"lua", "-lsocket", "-e", "x"},
		{"deno", "eval", "x"},
		// A value option that hides a flag is refused, so a wrong entry in
		// the table of value options cannot hide one.
		{"node", "--title", "-e", "x"},
		{"node", "--title", "-pe", "x"},
		// bun, npm, npx and pnpm are not in the table, so each letter of a
		// cluster counts.
		{"bun", "-pe", "process.env"},
		{"npx", "-yc", "env"},
	})
}

// TestTheWordsAfterTheProgramFileBelongToIt covers the other half of issue
// 77: a flag after the program file is a flag of the program, not of the
// interpreter.
func TestTheWordsAfterTheProgramFileBelongToIt(t *testing.T) {
	allowedAll(t, [][]string{
		{"perl", "-lan", "script.pl", "data.txt"},
		{"perl", "-w", "script.pl", "-e", "x"},
		{"ruby", "-rjson", "script.rb"},
		{"ruby", "-I", "lib", "script.rb"},
		{"python3", "-m", "pytest", "-q"},
		{"python3", "-m", "pytest", "-c", "pytest.ini"},
		{"python3", "-mpytest", "-q"},
		{"python3", "script.py", "-c", "config.yaml"},
		{"python3", "-u", "-W", "ignore", "script.py", "-i"},
		{"python3", "-X", "dev", "script.py"},
		{"python3", "--", "script.py", "-c", "x"},
		{"node", "--title", "x", "app.js"},
		{"node", "-r", "dotenv/config", "app.js", "-e"},
		{"node", "--inspect", "app.js"},
		{"node", "--max-old-space-size=4096", "app.js"},
		{"node", "--test"},
		{"node", "-c", "app.js"},
		{"php", "script.php", "-r"},
		{"php", "-d", "memory_limit=1G", "artisan", "serve"},
		{"php", "-S", "localhost:8000"},
		{"php", "-S", "localhost:8000", "-t", "public"},
		{"php", "-f", "script.php"},
		{"lua", "script.lua", "-e"},
		{"lua", "-l", "socket", "script.lua"},
		{"deno", "run", "-A", "main.ts"},
		{"deno", "fmt"},
		{"osascript", "script.scpt"},
		{"osascript", "-l", "JavaScript", "script.js"},
		{"bun", "run", "dev"},
		{"npm", "run", "build", "--", "-c"},
	})
}

// TestAProgramFromStandardInputIsRefused covers issue 79. An interpreter with
// no program file reads its program from standard input, and the rules cannot
// read a pipe.
func TestAProgramFromStandardInputIsRefused(t *testing.T) {
	refusedAll(t, "the interpreter reads its program from standard input", [][]string{
		{"python3"},
		{"python"},
		{"python3", "-"},
		{"python3", "-u"},
		{"python3", "-u", "-", "arg"},
		{"python3", "--", "-"},
		{"python3", "-i", "script.py"},
		{"python3", "-m"},
		{"node"},
		{"node", "-"},
		{"node", "-i"},
		{"node", "--interactive"},
		{"node", "-r", "dotenv/config"},
		{"perl"},
		{"perl", "-"},
		{"perl", "-w"},
		{"ruby"},
		{"ruby", "-"},
		{"lua"},
		{"lua", "-"},
		{"lua", "-i", "script.lua"},
		{"php"},
		{"php", "-"},
		{"php", "-a"},
		{"php", "-B", "x", "-R", "y"},
		{"php", "-E", "x"},
		{"R"},
		{"R", "--vanilla"},
		// R ignores a word that is not an option, and reads standard input.
		{"R", "script.R"},
		{"R", "-e", "Sys.getenv()"},
		{"Rscript", "-e", "Sys.getenv()"},
		{"Rscript", "-"},
		{"osascript"},
		{"osascript", "-"},
		{"osascript", "-e", `do shell script "env"`},
		{"osascript", "-l", "JavaScript", "-e", "x"},
		{"deno"},
		{"deno", "repl"},
		{"deno", "-"},
		{"deno", "run", "-"},
		{"bun", "-"},
	})
	allowedAll(t, [][]string{
		{"python3", "script.py"},
		{"python3", "-m", "http.server"},
		{"python3", "--version"},
		{"python3", "-V"},
		{"python3", "--help"},
		{"node", "app.js"},
		{"node", "--version"},
		{"node", "-v"},
		{"perl", "-v"},
		{"ruby", "--version"},
		{"php", "-v"},
		{"php", "-i"},
		{"php", "-S", "localhost:8000"},
		{"R", "-f", "script.R"},
		{"R", "--file=script.R"},
		{"R", "CMD", "build", "."},
		{"R", "--version"},
		{"Rscript", "file.R"},
		{"deno", "--version"},
		{"lua", "-v"},
	})
}

// TestAStandardInputRefusalSaysSo checks that the message names standard
// input, so the developer knows to name the file.
func TestAStandardInputRefusalSaysSo(t *testing.T) {
	err := Default().Check([]string{"python3"})
	var r *Refusal
	if !errors.As(err, &r) {
		t.Fatalf("bare python3 was not refused: %v", err)
	}
	if !strings.Contains(r.Rule, "standard input") || !strings.Contains(r.Advice, "name the file") {
		t.Errorf("the refusal does not explain the rule: %v", r)
	}
}

// TestAFileWithoutTheDashRuleAllowsABareInterpreter shows that the rule is a
// flag like any other: a policy file that leaves "-" out allows the bare call.
func TestAFileWithoutTheDashRuleAllowsABareInterpreter(t *testing.T) {
	p := Default()
	// A rule matches each form of the name, so both keys lose the rule.
	p.Agent.InlineCode["python"] = []string{"-c"}
	p.Agent.InlineCode["python3"] = []string{"-c"}
	if err := p.Check([]string{"python3"}); err != nil {
		t.Errorf("a file without the - rule still refused a bare python3: %v", err)
	}
	if err := p.Check([]string{"python3", "-Sc", "x"}); err == nil {
		t.Error("a file without the - rule stopped the -c rule too")
	}
}

// TestAProgramFromTheInputIsRefused covers issue 81. xargs, find -exec and
// fd -x put words from their input into the command they start.
func TestAProgramFromTheInputIsRefused(t *testing.T) {
	refusedAll(t, "a word from the input can be the program or a flag of it", [][]string{
		{"xargs", "-I{}", "{}"},
		{"xargs", "-I", "{}", "{}"},
		{"xargs", "-I", "X", "/usr/bin/X"},
		{"xargs", "-0I", "X", "X"},
		{"xargs", "-i", "{}"},
		{"xargs", "-iX", "X"},
		{"xargs", "--replace", "{}"},
		{"xargs", "--replace=X", "X"},
		{"xargs", "-J", "%", "%"},
		{"find", "/usr/bin", "-name", "env", "-exec", "{}", ";"},
		{"find", ".", "-exec", "./{}", "+"},
		{"find", ".", "-name", "x", "-exec", "rm", "{}", ";", "-exec", "{}", ";"},
		{"fd", "-x", "{}"},
		{"fd", "--exec", "{/}"},
		{"xargs", "nice"},
		{"xargs", "timeout", "5"},
		{"xargs", "npx"},
		{"xargs", "python3"},
		{"xargs", "-0", "python3"},
		{"xargs", "-n", "1", "node"},
		{"xargs", "-I{}", "python3", "{}"},
		{"xargs", "perl", "-w"},
		{"xargs", "git"},
		{"xargs", "git", "-C", "repo"},
		{"xargs", "-I{}", "git", "{}"},
		{"xargs", "ssh"},
		{"xargs", "php", "-S", "localhost:8000"},
		{"xargs", "deno", "run"},
		{"find", ".", "-exec", "nice", "{}", ";"},
		{"find", ".", "-exec", "git", "{}", ";"},
		{"find", ".", "-exec", "python3", "-c", "x", "{}", ";"},
		{"fd", "-x", "python3", "{}"},
		{"fd", "-x", "python3"},
		{"nice", "xargs", "-I{}", "{}"},
		{"xargs", "-I{}", "sh", "-c", "{}"},
	})
	allowedAll(t, [][]string{
		{"xargs"},
		{"xargs", "-I{}", "cp", "{}", "dst/"},
		{"xargs", "-0", "-n", "1", "rm"},
		{"xargs", "git", "add"},
		{"xargs", "git", "-C", "repo", "add"},
		{"xargs", "gofmt", "-l"},
		{"xargs", "python3", "lint.py"},
		{"xargs", "python3", "-m", "black"},
		{"xargs", "-I{}", "python3", "lint.py", "{}"},
		{"xargs", "node", "scripts/check.js"},
		{"find", ".", "-exec", "python3", "{}", ";"},
		{"find", ".", "-name", "*.go", "-exec", "gofmt", "-l", "{}", "+"},
		{"find", ".", "-exec", "git", "add", "{}", "+"},
		{"find", ".", "-exec", "nice", "gofmt", "-l", ";"},
		{"fd", "-e", "go", "-x", "gofmt", "-l"},
		{"fd", "-x", "python3", "lint.py", "{}"},
		{"fd", "-X", "rm"},
	})
}

// TestAnInputRefusalNamesTheProgramThatFeedsIt checks the message, so the
// developer knows which part of the command to change.
func TestAnInputRefusalNamesTheProgramThatFeedsIt(t *testing.T) {
	err := Default().Check([]string{"nice", "xargs", "python3"})
	var r *Refusal
	if !errors.As(err, &r) {
		t.Fatalf("nice xargs python3 was not refused: %v", err)
	}
	if r.Program != "xargs through nice" || !strings.Contains(r.Rule, "python") {
		t.Errorf("the refusal does not name both programs: %v", r)
	}
}

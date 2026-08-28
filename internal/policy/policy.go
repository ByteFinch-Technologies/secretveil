// Package policy decides which commands an AI agent may run.
//
// This is the second layer of the product and it is the weaker one. The first
// layer is the file itself: the .env file holds no secret, so there is nothing
// to read. This layer only narrows what an agent can do with a secret that
// "secretveil run" puts into a child process.
//
// Be honest about the limit. The rules here read the name of a program and its
// flags. They cannot read what the program does. An agent that runs
// "npm run dev" gets a pass, and the script behind that name can print the
// whole environment. The output filter is what stops the value from reaching
// the agent, not this package. See the adversarial test set, where case 3
// records exactly this.
//
// So the rules have a narrow purpose. They stop the one-line command whose
// whole purpose is to print the environment, because that command is the
// cheapest attack and the easiest to block.
package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// FileName is the name of the policy file inside the .secretveil directory.
const FileName = "policy.toml"

// Policy is the whole rule set.
type Policy struct {
	Agent Agent `toml:"agent"`
}

// Agent holds the rules that apply when an AI tool is the caller.
type Agent struct {
	// Enforce turns the rules on. A developer who finds them noisy can set it
	// to false, and then only the output filter is left. The file says so.
	Enforce bool `toml:"enforce"`
	// Allow names every program an agent may start. A program that is not in
	// the list is refused. An empty list means every program is allowed, which
	// is the setting for a developer who trusts their own agent.
	Allow []string `toml:"allow"`
	// Deny names a program an agent may never start, even when the allow list
	// is empty. These are the shells and the programs whose whole purpose is to
	// print the environment.
	Deny []string `toml:"deny"`
	// InlineCode maps a program to the flags that make it run code from the
	// command line. A flag like this turns any interpreter into a shell, so it
	// is refused even for a program in the allow list.
	InlineCode map[string][]string `toml:"inline_code"`
}

// Default returns the rules that apply when the project has no policy file.
//
// The default allow list is empty on purpose. A list of every build tool in the
// world is impossible to keep current, and a wrong refusal teaches a developer
// to turn the whole thing off. The deny list and the inline code rules are
// short, they are stable, and they catch the attack that matters.
func Default() *Policy {
	return &Policy{Agent: Agent{
		Enforce: true,
		Allow:   nil,
		Deny: []string{
			// A shell runs anything, so allowing one allows everything.
			"sh", "bash", "zsh", "dash", "fish", "ksh", "csh", "tcsh",
			"ash", "busybox", "pwsh", "powershell", "cmd", "cmd.exe",
			// These print the environment and do nothing else.
			"env", "printenv", "set", "export", "declare", "printf",
		},
		InlineCode: map[string][]string{
			"node": {"-e", "--eval", "-p", "--print"},
			"deno": {"eval"},
			// bun runs code from the command line in five ways. The pairs
			// -e and --eval, and -p and --print, evaluate an argument.
			// "bun -" and "bun run -" read the program from standard input.
			// "exec" runs a shell script. "repl" reads a program too.
			"bun":     {"-e", "--eval", "-p", "--print", "-", "exec", "repl"},
			"python":  {"-c"},
			"python3": {"-c"},
			"ruby":    {"-e"},
			"perl":    {"-e", "-E"},
			"php":     {"-r"},
			"lua":     {"-e"},
			"R":       {"-e"},
			"ssh":     {}, // any use, because it moves data off the machine
		},
	}}
}

// Load reads the policy for a project. A project with no policy file gets the
// default rules.
func Load(root string) (*Policy, error) {
	path := filepath.Join(root, ".secretveil", FileName)
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Default(), nil
	}
	if err != nil {
		return nil, err
	}

	// The default is the base, so a file that names only one rule keeps the
	// rest. A file that empties a list on purpose can still do so, because an
	// empty list in the file replaces the default list.
	p := Default()
	md, err := toml.Decode(string(body), p)
	if err != nil {
		return nil, fmt.Errorf("the policy file %s is not valid: %w", path, err)
	}
	for _, key := range md.Undecoded() {
		return nil, fmt.Errorf("the policy file %s holds a setting nobody knows: %s", path, key.String())
	}
	return p, nil
}

// Refusal explains why a command was refused.
type Refusal struct {
	// Program is the name the rule matched.
	Program string
	// Rule names the rule that fired, for the audit log.
	Rule string
	// Advice tells the developer how to allow the command.
	Advice string
}

func (r *Refusal) Error() string {
	return fmt.Sprintf("an AI agent may not run %s here: %s. %s", r.Program, r.Rule, r.Advice)
}

// Check reports whether an agent may run this command.
//
// It returns nil when the command is allowed. The caller passes the whole
// argument list, the same one that would go to the child process.
func (p *Policy) Check(args []string) error {
	if !p.Agent.Enforce || len(args) == 0 {
		return nil
	}
	name := programName(args[0])

	for _, d := range p.Agent.Deny {
		if name == d {
			return &Refusal{
				Program: name,
				Rule:    "it is in the deny list, because it can print the whole environment",
				Advice:  "Run it yourself in your own terminal, or ask secretveil to run the real command instead of a shell around it.",
			}
		}
	}

	if flags, ok := p.Agent.InlineCode[name]; ok {
		if len(flags) == 0 {
			return &Refusal{
				Program: name,
				Rule:    "an agent may not run it at all",
				Advice:  "Run it yourself in your own terminal.",
			}
		}
		if bad := firstMatch(args[1:], flags); bad != "" {
			// A word such as "exec" or "repl" is a subcommand and not a
			// flag. Calling it a flag makes the developer look for a flag
			// that is not there.
			kind := "flag"
			if !strings.HasPrefix(bad, "-") {
				kind = "subcommand"
			}
			return &Refusal{
				Program: name,
				Rule: fmt.Sprintf("the %s %s runs code straight from the command line, which makes %s a shell",
					kind, bad, name),
				Advice: "Put the code in a file and run the file.",
			}
		}
	}

	if len(p.Agent.Allow) > 0 && !contains(p.Agent.Allow, name) {
		return &Refusal{
			Program: name,
			Rule:    "it is not in the allow list of this project",
			Advice: fmt.Sprintf("Add %q to the allow list in .secretveil/%s if an agent should be able to run it.",
				name, FileName),
		}
	}
	return nil
}

// firstMatch returns the first argument that is one of the flags.
//
// A flag joined to its value with an equals sign counts, so --eval=x is caught
// as well as --eval x. Everything after a bare -- is a value and not a flag.
func firstMatch(args, flags []string) string {
	for _, a := range args {
		if a == "--" {
			return ""
		}
		head := a
		if i := strings.IndexByte(a, '='); i > 0 {
			head = a[:i]
		}
		if contains(flags, head) {
			return head
		}
	}
	return ""
}

// programName reduces a path to the name of the program.
//
// A path is enough to defeat a name test, so /bin/bash and bash have to give
// the same answer. The .exe ending is removed for the same reason.
//
// Both the slash and the backslash count as a separator, whatever machine this
// runs on. filepath is not used here, because filepath knows only the separator
// of the machine, and on Linux it would read the whole of
// C:\Windows\System32\cmd.exe as one name and let the command through. The
// policy file is checked into the project, so the same command has to give the
// same answer on every machine in the team.
func programName(arg string) string {
	if i := strings.LastIndexAny(arg, `/\`); i >= 0 {
		arg = arg[i+1:]
	}
	return strings.TrimSuffix(strings.TrimSuffix(arg, ".exe"), ".EXE")
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// Sample is the policy file that init writes. It documents every rule, because
// a security setting nobody understands gets turned off.
const Sample = `# How much may an AI agent do in this project?
#
# These rules are the second layer, and they are the weaker one. The first
# layer is your .env file, which now holds handles and no secrets. This file
# only narrows what an agent may start with "secretveil run".
#
# The rules read the name of a program and its flags. They cannot read what the
# program does. An agent that runs "npm run dev" passes these rules, and the
# script behind that name can still print the whole environment. The output
# filter is what stops the value from reaching the agent.

[agent]

# Turn the rules off if they get in your way. The output filter keeps working.
enforce = true

# Programs an agent may start. An empty list allows every program that the
# rules below do not refuse.
allow = []

# Programs an agent may never start. A shell runs anything, so it is here.
deny = [
  "sh", "bash", "zsh", "dash", "fish", "ksh", "csh", "tcsh",
  "ash", "busybox", "pwsh", "powershell", "cmd",
  "env", "printenv", "set", "export", "declare", "printf",
]

# Flags that make a program run code straight from the command line. A flag
# like this turns an interpreter into a shell.
[agent.inline_code]
node = ["-e", "--eval", "-p", "--print"]
deno = ["eval"]
bun = ["-e", "--eval", "-p", "--print", "-", "exec", "repl"]
python = ["-c"]
python3 = ["-c"]
ruby = ["-e"]
perl = ["-e", "-E"]
php = ["-r"]
lua = ["-e"]
R = ["-e"]
# An empty list means the program is refused whatever its flags are.
ssh = []
`

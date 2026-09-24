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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
			//
			// firstMatch reads every argument and not only the first one, so
			// "bun add repl" is refused as well. That is deliberate. A rule
			// that looked at the position alone would let "bun --silent exec"
			// through, and an agent must not have that door.
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
	p, _, err := LoadWithHash(root)
	return p, err
}

// LoadWithHash is Load, and it also returns the SHA-256 of the bytes it read,
// as hex. The hash is empty when the project has no policy file.
//
// The rules and the hash come from one read. With two reads, the file could
// change between them, and an approval of one file would pass another.
func LoadWithHash(root string) (*Policy, string, error) {
	path := filepath.Join(root, ".secretveil", FileName)
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Default(), "", nil
	}
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(body)
	p, err := decode(path, body)
	if err != nil {
		return nil, "", err
	}
	return p, hex.EncodeToString(sum[:]), nil
}

func decode(path string, body []byte) (*Policy, error) {
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
	normalize(p)
	return p, nil
}

// normalize reduces every program name in p with programName, one time, when
// the file is read.
//
// Check reduces the command to its name, so a rule must hold the name too. A
// file that wrote /bin/printenv in the deny list looked complete to Weaker,
// which reduced both sides, and matched nothing in Check, which did not. An
// agent could then turn the deny list off with no approval. With one form in
// the policy, every reader of it gives the same answer.
//
// Two inline_code keys can name one program, such as node and /usr/bin/node.
// Their flags are joined. An empty list refuses every use, so an empty list on
// either key wins.
func normalize(p *Policy) {
	for i, name := range p.Agent.Deny {
		p.Agent.Deny[i] = programName(name)
	}
	for i, name := range p.Agent.Allow {
		p.Agent.Allow[i] = programName(name)
	}
	inline := make(map[string][]string, len(p.Agent.InlineCode))
	for prog, flags := range p.Agent.InlineCode {
		name := programName(prog)
		got, seen := inline[name]
		switch {
		case !seen:
			inline[name] = append([]string{}, flags...)
		case len(got) == 0 || len(flags) == 0:
			inline[name] = []string{}
		default:
			for _, flag := range flags {
				if !contains(got, flag) {
					got = append(got, flag)
				}
			}
			inline[name] = got
		}
	}
	p.Agent.InlineCode = inline
}

// ApprovalKey names the setting in the encrypted store that holds the hash of
// the policy file a human approved.
const ApprovalKey = "policy_sha256"

// Weaker returns one reason for each place where p gives an agent more than
// the defaults do. A policy that only adds rules gives no reason.
//
// The policy file sits inside the project, and an agent writes files in the
// project all day. So a file that turns a default rule off may be the work of
// the agent it is meant to stop. The caller uses the reasons to decide whether
// the file needs the approval of a human.
func Weaker(p *Policy) []string {
	d := Default()
	var out []string
	if !p.Agent.Enforce {
		out = append(out, "enforce is false")
	}
	// Check compares the name after programName, so cmd.exe and cmd are one
	// rule. The comparison here does the same.
	denied := map[string]bool{}
	for _, name := range p.Agent.Deny {
		denied[programName(name)] = true
	}
	seen := map[string]bool{}
	for _, name := range d.Agent.Deny {
		name = programName(name)
		if !denied[name] && !seen[name] {
			seen[name] = true
			out = append(out, fmt.Sprintf("the deny list does not hold %s", name))
		}
	}

	progs := make([]string, 0, len(d.Agent.InlineCode))
	for prog := range d.Agent.InlineCode {
		progs = append(progs, prog)
	}
	sort.Strings(progs)
	for _, prog := range progs {
		want := d.Agent.InlineCode[prog]
		got, ok := p.Agent.InlineCode[prog]
		switch {
		case !ok:
			out = append(out, fmt.Sprintf("inline_code has no rule for %s", prog))
		case len(want) == 0 && len(got) > 0:
			// An empty list refuses every use. A list of flags refuses
			// fewer.
			out = append(out, fmt.Sprintf("%s is no longer refused for every use", prog))
		default:
			for _, flag := range want {
				if !contains(got, flag) {
					out = append(out, fmt.Sprintf("inline_code for %s does not hold %s", prog, flag))
				}
			}
		}
	}
	return out
}

// Floor returns p with every default rule put back. The allow list of p stays,
// because an allow list only takes power away.
//
// This is the policy an agent gets when the file is weaker than the defaults
// and no human approved it. A file that only adds rules keeps all of them.
func Floor(p *Policy) *Policy {
	d := Default()
	out := &Policy{Agent: Agent{
		Enforce:    true,
		Allow:      append([]string(nil), p.Agent.Allow...),
		Deny:       append([]string(nil), p.Agent.Deny...),
		InlineCode: map[string][]string{},
	}}
	for _, name := range d.Agent.Deny {
		if !contains(out.Agent.Deny, name) {
			out.Agent.Deny = append(out.Agent.Deny, name)
		}
	}
	for prog, flags := range p.Agent.InlineCode {
		out.Agent.InlineCode[prog] = append([]string(nil), flags...)
	}
	for prog, want := range d.Agent.InlineCode {
		got, ok := out.Agent.InlineCode[prog]
		switch {
		case !ok || len(want) == 0:
			out.Agent.InlineCode[prog] = append([]string(nil), want...)
		default:
			for _, flag := range want {
				if !contains(got, flag) {
					got = append(got, flag)
				}
			}
			out.Agent.InlineCode[prog] = got
		}
	}
	return out
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

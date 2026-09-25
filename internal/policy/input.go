package policy

import (
	"fmt"
	"strings"
)

// feeds names each program that puts words from its input into the command
// that it starts. The rules cannot read those words. "echo env | xargs -I{} {}"
// runs env, and "xargs python3" gives python a -c that came from the input.
//
// For each program, the function returns the commands that it starts, as the
// rules can see them. It returns a refusal when a word from the input can be
// the program, or can be an option of a program that runs code from its
// arguments.
var feeds = map[string]func(p *Policy, rest []string) ([][]string, error){
	"xargs": (*Policy).xargs,
	"find":  (*Policy).find,
	"fd":    (*Policy).fd,
}

// xargsValues are the short options of GNU and BSD xargs that take a value.
// -e, -i and -l take a value only when it is joined to the letter.
const xargsValues = "adEIJLnPRSs"

// xargsLong are the long options of GNU xargs that take the next word as their
// value.
var xargsLong = []string{"--arg-file", "--delimiter", "--max-args", "--max-procs", "--max-chars", "--process-slot-var"}

// xargs finds the command that xargs starts and the replace string, if any.
//
// Without a replace string, xargs adds the words from its input to the end of
// the command. With -I, -J, -i or --replace, it puts them where the replace
// string is.
func (p *Policy) xargs(rest []string) ([][]string, error) {
	repl := ""
	i := 0
options:
	for ; i < len(rest); i++ {
		a := rest[i]
		switch {
		case a == "--":
			i++
			break options
		case !strings.HasPrefix(a, "-") || a == "-":
			break options
		case strings.HasPrefix(a, "--"):
			head, val, joined := strings.Cut(a, "=")
			switch {
			case head == "--replace":
				repl = "{}"
				if joined {
					repl = val
				}
			case !joined && contains(xargsLong, head):
				i++
			}
		default:
			for j := 1; j < len(a); j++ {
				c := a[j]
				joined := a[j+1:]
				if c == 'e' || c == 'i' || c == 'l' {
					if c == 'i' {
						repl = "{}"
						if joined != "" {
							repl = joined
						}
					}
					break
				}
				if strings.IndexByte(xargsValues, c) < 0 {
					continue
				}
				v := joined
				if v == "" && i+1 < len(rest) {
					i++
					v = rest[i]
				}
				if c == 'I' || c == 'J' {
					repl = v
				}
				break
			}
		}
	}
	cmd := rest[i:]
	if len(cmd) == 0 {
		return nil, nil
	}
	if err := p.fed("xargs", cmd, placeholders(repl), false); err != nil {
		return nil, err
	}
	return [][]string{cmd}, nil
}

// find returns the command of each -exec, -execdir, -ok and -okdir clause.
//
// find puts a path from the file system only where {} is, and the path starts
// with the start path, so it is never an option. A clause with no {} holds no
// word from the input.
func (p *Policy) find(rest []string) ([][]string, error) {
	var cmds [][]string
	for i := 0; i < len(rest); i++ {
		if !contains([]string{"-exec", "-execdir", "-ok", "-okdir"}, rest[i]) {
			continue
		}
		j := i + 1
		for j < len(rest) && rest[j] != ";" && !(rest[j] == "+" && rest[j-1] == "{}") {
			j++
		}
		cmd := rest[i+1 : j]
		i = j
		if len(cmd) == 0 {
			continue
		}
		if holds(cmd, []string{"{}"}) {
			if err := p.fed("find", cmd, []string{"{}"}, true); err != nil {
				return nil, err
			}
		}
		cmds = append(cmds, cmd)
	}
	return cmds, nil
}

// fdHolders are the placeholders of fd. Without one of them, fd adds the path
// to the end of the command.
var fdHolders = []string{"{}", "{/}", "{//}", "{.}", "{/.}"}

// fd returns the command after -x, --exec, -X or --exec-batch. The command
// takes every word after the option, up to a ";" word.
func (p *Policy) fd(rest []string) ([][]string, error) {
	for i, a := range rest {
		if !contains([]string{"-x", "--exec", "-X", "--exec-batch"}, a) {
			continue
		}
		j := i + 1
		for j < len(rest) && rest[j] != ";" {
			j++
		}
		cmd := rest[i+1 : j]
		if len(cmd) == 0 {
			return nil, nil
		}
		if err := p.fed("fd", cmd, fdHolders, false); err != nil {
			return nil, err
		}
		return [][]string{cmd}, nil
	}
	return nil, nil
}

// placeholders returns the replace string of xargs as a list, or nil.
func placeholders(repl string) []string {
	if repl == "" {
		return nil
	}
	return []string{repl}
}

// holds reports whether a word in cmd holds one of the placeholders.
func holds(cmd, marks []string) bool {
	for _, w := range cmd {
		for _, m := range marks {
			if strings.Contains(w, m) {
				return true
			}
		}
	}
	return false
}

// fed applies the rules to a command that gets words from the input of via.
//
// The first word must not hold a placeholder, because then the input names the
// program. The first word must not be a wrapper or a program with inline code
// rules either, because a word from the input can then be the program or one
// of its flags. Two cases are safe and allowed:
//
//   - an interpreter whose program file is in the command, because the words
//     from the input come after it and go to the program. For find, the
//     program file can be the placeholder, because the path is never an
//     option.
//   - git with its subcommand in the command, such as "xargs git add".
func (p *Policy) fed(via string, cmd, marks []string, fileMayBeMark bool) error {
	if holds(cmd[:1], marks) {
		return &Refusal{
			Program: via,
			Rule:    "the name of the program it starts comes from its input, and the rules cannot read that name",
			Advice:  "Name the program in the command, and give only the file names as input.",
		}
	}
	all := forms(cmd[0])
	name := all[len(all)-1]
	flags, inline := p.inline(all)
	_, wraps := wrappers[name]
	if !inline && !wraps {
		return nil
	}
	if inline {
		if it, ok := interpreters[name]; ok {
			bad, prog := it.scan(cmd[1:], flags)
			// A flag in plain view gets the refusal of the normal check,
			// which names the flag. "-" is not in plain view: here the
			// options name no program file, and the input can name one.
			if bad != "" && bad != "-" {
				return nil
			}
			if prog >= 0 && (fileMayBeMark || !holds(cmd[1+prog:2+prog], marks)) {
				return nil
			}
		}
		if values, ok := globalOptions[name]; ok {
			lead := leading(cmd[1:], values)
			if n := 1 + len(lead); n < len(cmd) && cmd[n] != "--" && !holds(cmd[n:n+1], marks) {
				return nil
			}
		}
	}
	return &Refusal{
		Program: via,
		Rule: fmt.Sprintf("it gives words from its input to %s, and a word the rules cannot read can make %s run any code",
			name, name),
		Advice: "Name the program file or the subcommand in the command, or put the commands in a script file and run the file.",
	}
}

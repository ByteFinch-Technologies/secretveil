package policy

import "strings"

// interp tells how an interpreter reads its options.
//
// An interpreter reads its options up to the word that names the program
// file. The words after that word belong to the program, so "python3 app.py
// -c config.yaml" gives -c to app.py and not to python. An interpreter also
// reads a cluster of short options, so "perl -lne" is -l, -n and -e. The rules
// must read the words the same way, or they refuse the wrong command and let
// the right one through.
type interp struct {
	// values are the options that take the next word as their value.
	values []string
	// stop are the short option letters that take a value. In a cluster, the
	// rest of the word after such a letter is the value, so "ruby -rjson"
	// loads json and does not turn on -j, -s, -o and -n.
	stop string
	// script are the options whose value names the program and ends the
	// options, such as "python -m pytest".
	script []string
	// named are the options whose value names the program while the options
	// go on, such as "php -S localhost:8000 -t public".
	named []string
	// program are the options with no value that name the program, such as
	// "node --test", which finds the test files by itself.
	program []string
	// exit are the options that print something and stop. A call with one of
	// them and no program reads no program from standard input.
	exit []string
	// rest are the options after which each word is an argument of the
	// program, such as "R --args".
	rest []string
	// noFile is true when a word that is not an option does not name a
	// program file. "R script.R" ignores the word and reads standard input.
	noFile bool
	// commands are the words that name what to run when noFile is true.
	commands []string
	// subcommand is true when the first word that is not an option is a
	// subcommand and not a program file, as for deno.
	subcommand bool
}

// interpreters holds each interpreter whose options the rules read with scan.
// The keys are in the form that programName gives, so python3.12 uses the
// entry for python.
//
// A program with inline code rules that is not here gets a simpler test: each
// word before "--" is read, and each letter of a cluster counts. That test
// refuses more than it must, and it fails closed.
//
// A value option that is not in this table ends the options too early, and
// the rules then read its value as the program file. The flags after it are
// not read. Each option here was checked against the manual of the
// interpreter, and a value word that looks like an inline code flag is
// refused, so a mistake in the table cannot hide a flag such as -e.
var interpreters = map[string]interp{
	"python": {
		values: []string{"-W", "-X", "-Q", "--check-hash-based-pycs"},
		stop:   "mWXQ",
		script: []string{"-m"},
		exit:   []string{"-h", "-?", "--help", "--help-env", "--help-xoptions", "--help-all", "-V", "--version"},
	},
	"perl": {
		values: []string{"-I"},
		stop:   "CdDFiIMmxV",
		exit:   []string{"-v", "-V", "-h", "--help", "--version"},
	},
	"ruby": {
		values: []string{"-C", "-E", "-I", "-r", "--enable", "--disable", "--encoding", "--external-encoding", "--internal-encoding"},
		stop:   "CEFiIKrTWx",
		exit:   []string{"-h", "--help", "--version", "--copyright"},
	},
	"node": {
		values: []string{
			"-r", "--require", "--import", "--loader", "--experimental-loader", "-C", "--conditions",
			"--title", "--env-file", "--env-file-if-exists", "--input-type", "--inspect-port", "--debug-port",
			"--redirect-warnings", "--diagnostic-dir", "--heapsnapshot-signal", "--icu-data-dir",
			"--openssl-config", "--tls-cipher-list", "--unhandled-rejections", "--secure-heap",
			"--secure-heap-min", "--max-http-header-size", "--disable-warning", "--watch-path",
			"--test-reporter", "--test-reporter-destination", "--test-name-pattern", "--test-skip-pattern",
			"--test-concurrency", "--test-timeout", "--test-shard", "--experimental-policy",
			"--policy-integrity", "--dns-result-order", "--cpu-prof-dir", "--cpu-prof-name",
			"--cpu-prof-interval", "--heap-prof-dir", "--heap-prof-name", "--heap-prof-interval",
			"--report-dir", "--report-directory", "--report-filename", "--report-signal",
			"--localstorage-file", "--experimental-sea-config", "--snapshot-blob",
			"--trace-event-categories", "--trace-event-file-pattern", "--use-largepages",
		},
		stop:    "rC",
		named:   []string{"--run"},
		program: []string{"--test"},
		exit:    []string{"-h", "--help", "-v", "--version", "--v8-options", "--completion-bash"},
	},
	"php": {
		values: []string{"-c", "-d", "-z", "-t", "--php-ini", "--define", "--zend-extension", "--docroot"},
		stop:   "cdztfFS",
		named:  []string{"-f", "-F", "-S", "--file", "--process-file", "--server"},
		exit: []string{"-h", "--help", "-i", "--info", "-m", "--modules", "-v", "--version", "--ini",
			"--rf", "--rc", "--re", "--rz", "--ri"},
	},
	"lua": {
		values: []string{"-l"},
		stop:   "l",
		exit:   []string{"-v"},
	},
	"r": {
		values:   []string{"-d", "-g"},
		stop:     "dgf",
		named:    []string{"-f", "--file"},
		exit:     []string{"-h", "--help", "--version"},
		rest:     []string{"--args"},
		noFile:   true,
		commands: []string{"CMD", "RHOME"},
	},
	"rscript": {
		exit: []string{"--help", "--version"},
	},
	"osascript": {
		values: []string{"-l", "-s"},
		stop:   "ls",
	},
	"deno": {
		values:     []string{"-L", "--log-level"},
		exit:       []string{"-h", "--help", "-V", "--version"},
		subcommand: true,
	},
}

// scan reads the options of an interpreter the way the interpreter reads them.
//
// It returns the first inline code flag in the options, or "". The flag "-"
// means that the interpreter reads its program from standard input, because
// the options name no program or they name the program "-".
//
// It also returns the index of the word that names the program file when the
// options end at that word. It returns -1 when the options name no program
// file, or when the words after the program can still be options. A caller
// that adds words to the end of the command, such as xargs, is safe only when
// the index is not -1.
func (it interp) scan(args, flags []string) (bad string, prog int) {
	named := false
	exits := false
	// bare is the result when the words end and no word ended the options.
	bare := func() (string, int) {
		if !named && !exits && contains(flags, "-") {
			return "-", -1
		}
		return "", -1
	}
	// value skips the value of an option. A value that looks like an inline
	// code flag is refused, so a wrong entry in values cannot hide the flag.
	value := func(i int) (string, int) {
		if i < len(args) && len(args[i]) > 1 && strings.HasPrefix(args[i], "-") {
			if f := match(args[i], flags); f != "" {
				return f, i
			}
		}
		return "", i
	}

	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-":
			if contains(flags, "-") {
				return "-", -1
			}
			return "", i

		case a == "--":
			if i+1 == len(args) {
				return bare()
			}
			if args[i+1] == "-" && contains(flags, "-") {
				return "-", -1
			}
			return "", i + 1

		case contains(it.rest, a):
			return bare()

		case !strings.HasPrefix(a, "-"):
			if it.subcommand {
				if contains(flags, a) {
					return a, -1
				}
				// A subcommand reads its own options, so the words after
				// it get the simple test. "deno run -" is refused too.
				return anyMatch(args[i+1:], flags), -1
			}
			if it.noFile && !contains(it.commands, a) {
				continue
			}
			return "", i

		case strings.HasPrefix(a, "--"):
			head, _, joined := strings.Cut(a, "=")
			switch {
			case contains(flags, head):
				return head, -1
			case contains(it.script, head):
				if joined {
					return "", i
				}
				if i+1 < len(args) {
					return "", i + 1
				}
				return bare()
			case contains(it.named, head):
				named = true
			case contains(it.program, head):
				named = true
			case contains(it.exit, head):
				exits = true
			}
			if !joined && (contains(it.values, head) || contains(it.named, head)) {
				var f string
				if f, i = value(i + 1); f != "" {
					return f, -1
				}
			}

		default:
			// A short option, alone or in a cluster such as "-lne".
			switch {
			case contains(flags, a):
				return a, -1
			case contains(it.script, a):
				if i+1 < len(args) {
					return "", i + 1
				}
				return bare()
			case contains(it.named, a) || contains(it.values, a):
				named = named || contains(it.named, a)
				var f string
				if f, i = value(i + 1); f != "" {
					return f, -1
				}
				continue
			case contains(it.exit, a):
				exits = true
				continue
			}
			for j := 1; j < len(a); j++ {
				c := a[j]
				// A digit is the value of -0 or -l in perl and ruby.
				if c >= '0' && c <= '9' {
					continue
				}
				f := "-" + string(c)
				if contains(flags, f) {
					return f, -1
				}
				if contains(it.exit, f) {
					exits = true
				}
				if strings.IndexByte(it.stop, c) < 0 {
					continue
				}
				// The rest of the word is the value of this letter. With no
				// rest, the next word is the value.
				last := j+1 == len(a)
				switch {
				case contains(it.script, f):
					if !last {
						return "", i
					}
					if i+1 < len(args) {
						return "", i + 1
					}
					return bare()
				case contains(it.named, f):
					named = true
					if last {
						if f, i = value(i + 1); f != "" {
							return f, -1
						}
					}
				case last && contains(it.values, f):
					if f, i = value(i + 1); f != "" {
						return f, -1
					}
				}
				break
			}
		}
	}
	return bare()
}

// match reports the inline code flag in one word, or "".
//
// A flag joined to its value with an equals sign counts, and so does each
// letter of a cluster of short options, so "-pe" gives -e.
func match(a string, flags []string) string {
	head := a
	if i := strings.IndexByte(a, '='); i > 0 {
		head = a[:i]
	}
	if contains(flags, head) {
		return head
	}
	if len(a) > 2 && a[0] == '-' && a[1] != '-' {
		for j := 1; j < len(a); j++ {
			if a[j] >= '0' && a[j] <= '9' {
				continue
			}
			if f := "-" + string(a[j]); contains(flags, f) {
				return f
			}
		}
	}
	return ""
}

// anyMatch returns the first inline code flag in the words before "--", with
// each letter of a cluster read as a flag. It is the test for a program that
// is not in interpreters. It does not know which words are values, so it
// refuses more than it must.
func anyMatch(args, flags []string) string {
	for _, a := range args {
		if a == "--" {
			return ""
		}
		if f := match(a, flags); f != "" {
			return f
		}
	}
	return ""
}

// inlineFlag returns the first word or letter in args that makes the program
// run code from the command line, or "".
func inlineFlag(name string, args, flags []string) string {
	if it, ok := interpreters[name]; ok {
		bad, _ := it.scan(args, flags)
		return bad
	}
	if values, ok := globalOptions[name]; ok {
		return firstMatch(leading(args, values), flags)
	}
	return anyMatch(args, flags)
}

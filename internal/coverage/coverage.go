// Package coverage finds a credential that secretveil does not cover.
//
// secretveil puts a handle into a .env file. A project holds other files that
// carry a credential in plaintext, and an agent reads those files as easily as
// it reads a .env file. Before this package existed, doctor said "nothing is at
// risk" while an npm token sat in .npmrc beside it. That report was worse than
// no report, because it told the developer to stop looking.
//
// Every rule here is built for precision and not for recall. A rule fires only
// on a line that clearly holds a live value. The list of rules is short on
// purpose: a check that cries wolf gets switched off, and then it protects
// nobody.
package coverage

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// maxFileSize is the largest file a rule reads. A credential file is small. A
// file above this size is a data set that shares a name by accident.
const maxFileSize = 1 << 20

// Finding is one file that holds a credential secretveil does not cover.
type Finding struct {
	// Path is the file, as it was walked.
	Path string `json:"path"`
	// Kind names the rule that fired. It is shown to the human.
	Kind string `json:"kind"`
	// Lines names each line number that looks like a credential.
	Lines []int `json:"lines"`
	// Advice is the one thing the developer does next.
	Advice string `json:"advice"`
}

// rule describes one kind of credential file.
type rule struct {
	// kind is the name in the report.
	kind string
	// match reports whether a path is this kind of file. It gets the whole
	// path and the base name, because one name alone is not always enough:
	// config.json is a Docker login only inside a .docker directory.
	match func(path, base string) bool
	// line reports whether one line holds a live credential.
	//
	// The last capture group must be the value. hits reads that group and
	// drops the line when the value is only a placeholder, so a rule whose
	// last group is something else would report a file that is already safe.
	line *regexp.Regexp
	// advice is what the developer does next.
	advice string
}

// placeholder reports whether a value is already a reference and not a secret.
//
// A file that says ${NPM_TOKEN} or sv://npm_token holds no secret, so a rule
// that fires on it would be noise. The check is on the text of the value,
// because only the text says whether the work was already done.
var placeholder = regexp.MustCompile(`(\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|sv://|<[^>]*>|xxx+|\.\.\.|CHANGEME|YOUR_)`)

// exact builds a name test for a fixed set of base names.
func exact(names ...string) func(path, base string) bool {
	set := map[string]bool{}
	for _, n := range names {
		set[n] = true
	}
	return func(_, base string) bool { return set[base] }
}

// rules holds every kind of credential file this package knows.
//
// Each entry names a file format that carries a credential in plaintext and
// that secretveil does not rewrite. A format moves out of this list only when
// the migration learns to put a reference into it.
var rules = []rule{
	{
		kind:   ".npmrc",
		match:  exact(".npmrc"),
		line:   regexp.MustCompile(`(?i)^\s*(//[^\s=]*:)?_(authToken|auth|password)\s*=\s*(\S+)`),
		advice: "This is an npm registry credential. Move it out of the file, or rotate it.",
	},
	{
		kind:   ".netrc",
		match:  exact(".netrc", "_netrc"),
		line:   regexp.MustCompile(`(?i)\bpassword\s+(\S+)`),
		advice: "curl, git and ftp read this file directly. Nothing can put a reference in it.",
	},
	{
		kind:   ".yarnrc.yml",
		match:  exact(".yarnrc.yml", ".yarnrc.yaml", ".yarnrc"),
		line:   regexp.MustCompile(`(?i)^\s*npmAuth(Token|Ident)\s*[:=]\s*("?)(\S+)`),
		advice: "yarn expands ${VAR} here. Put the value in a variable and name the variable instead.",
	},
	{
		kind:   ".pypirc",
		match:  exact(".pypirc"),
		line:   regexp.MustCompile(`(?i)^\s*password\s*[:=]\s*(\S+)`),
		advice: "This is a package index credential. Use a keyring or a token in the environment.",
	},
	{
		kind:   ".pgpass",
		match:  exact(".pgpass"),
		line:   regexp.MustCompile(`^[^#:\s][^:]*:[^:]*:[^:]*:[^:]*:(\S+)`),
		advice: "libpq reads this file directly. Use a connection string in the environment instead.",
	},
	{
		kind:   ".git-credentials",
		match:  exact(".git-credentials"),
		line:   regexp.MustCompile(`://[^:/@\s]+:([^@/\s]+)@`),
		advice: "This holds a git password in the clear. Use a credential helper instead.",
	},
	{
		kind: "docker config",
		// config.json is too common a name to claim on its own. Only the one
		// inside a .docker directory is a registry login.
		match: func(path, base string) bool {
			if base == ".dockercfg" {
				return true
			}
			return base == "config.json" && filepath.Base(filepath.Dir(path)) == ".docker"
		},
		line:   regexp.MustCompile(`(?i)"(auth|password|identitytoken)"\s*:\s*"([^"]+)"`),
		advice: "This holds a registry login. Use a credential helper instead.",
	},
	{
		kind:   "aws credentials",
		match:  exact("credentials"),
		line:   regexp.MustCompile(`(?i)^\s*aws_(secret_access_key|session_token)\s*=\s*(\S+)`),
		advice: "Use a named profile with the AWS credential process, or a role.",
	},
	{
		kind:   ".envrc",
		match:  exact(".envrc"),
		line:   regexp.MustCompile(`(?i)^\s*export\s+\w*(SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY)\w*\s*=\s*(\S+)`),
		advice: "direnv runs this file as a shell script. Move the value into a .env file.",
	},
	{
		kind: "terraform variables",
		match: func(_, base string) bool {
			return base == "terraform.tfvars" || strings.HasSuffix(base, ".auto.tfvars")
		},
		line:   regexp.MustCompile(`(?i)^\s*\w*(secret|token|password|private_key|access_key)\w*\s*=\s*"([^"]+)"`),
		advice: "Terraform reads this file directly. Pass the value with TF_VAR_ from the environment.",
	},
}

// Scan walks a tree and returns every credential file that is not covered.
//
// skipDir names a directory to walk past. covered reports whether the migration
// already puts a reference into a path, and a covered path is never reported
// here. That keeps one file from being named by two different checks once the
// migration learns a new format.
//
// A symbolic link is never followed and never read, for the same reason the
// migration never follows one: a file inside the project can point at any file
// on the machine.
func Scan(root string, skipDir func(name string) bool, covered func(path string) bool) ([]Finding, error) {
	var out []Finding

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, werr error) error {
		if werr != nil {
			return nil
		}
		if d.IsDir() {
			if path != root && skipDir != nil && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		r, ok := ruleFor(path, d.Name())
		if !ok {
			return nil
		}
		if covered != nil && covered(path) {
			return nil
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() > maxFileSize {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		if lines := hits(body, r); len(lines) > 0 {
			out = append(out, Finding{Path: path, Kind: r.kind, Lines: lines, Advice: r.advice})
		}
		return nil
	})

	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, err
}

// ruleFor returns the rule for a path.
func ruleFor(path, base string) (rule, bool) {
	for _, r := range rules {
		if r.match(path, base) {
			return r, true
		}
	}
	return rule{}, false
}

// hits returns the line number of every line that holds a live credential.
func hits(body []byte, r rule) []int {
	if bytes.IndexByte(body, 0) >= 0 {
		// A binary file shares a name by accident. config.json is a real case,
		// because the name is common.
		return nil
	}
	var out []int
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64*1024), maxFileSize)
	for n := 1; sc.Scan(); n++ {
		text := sc.Text()
		trimmed := strings.TrimSpace(text)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		m := r.line.FindStringSubmatch(text)
		if m == nil {
			continue
		}
		if placeholder.MatchString(m[len(m)-1]) {
			continue
		}
		out = append(out, n)
	}
	return out
}

// Kinds returns the name of every format this package knows, in order. doctor
// prints it so the developer can see the limit of the check.
func Kinds() []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range rules {
		if !seen[r.kind] {
			seen[r.kind] = true
			out = append(out, r.kind)
		}
	}
	return out
}

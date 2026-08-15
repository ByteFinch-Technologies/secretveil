// Package npmrc reads and rewrites an .npmrc file without loss.
//
// # Why this file needs its own treatment
//
// An .npmrc file cannot hold an sv:// handle. npm reads the file straight from
// disk and sends the value it finds to the registry, so a handle would go over
// the wire as if it were the token. There is no precedence rule to lean on
// here, which is what makes a .env file work: dotenv, Vite and Next.js all let
// a variable already in the environment beat the file.
//
// npm gives one other opening, and it was measured before this package was
// written. npm expands ${VAR} inside an .npmrc from the process environment. An
// unset variable is left alone as the literal text ${VAR}, so a project that
// forgets to use "secretveil run" fails at the registry with a clear refusal
// instead of leaking anything. This is recorded as D7 in docs/decisions.md.
//
// So the rewrite target here is ${SV_NPMRC_...} and never sv://. The value goes
// into the same store, and "secretveil run" puts it in the child environment
// under that name.
//
// # The parser is deliberately narrow
//
// npm reads this file with an ini parser, and that parser does not agree with
// the .env parser on quoting or on inline comments. Rather than guess which
// reading is right, this package rewrites a line only when the value is a plain
// token: no space, no quote, no comment character. Every real registry token
// looks like that. A value of any other shape is left alone and reported, so a
// disagreement between the two readers can never put the wrong value in the
// store or the wrong bytes in the file.
//
// # The contract
//
// If no line is marked dirty, Bytes returns exactly the bytes that Parse
// received.
package npmrc

import (
	"regexp"
	"strings"
)

// FileNames holds every base name this package reads.
var FileNames = []string{".npmrc"}

// IsFile reports whether a base name is an .npmrc file.
func IsFile(base string) bool {
	for _, n := range FileNames {
		if base == n {
			return true
		}
	}
	return false
}

// RefPrefix starts the reference of every secret that came from an .npmrc file.
// It keeps these references apart from the ones a .env variable produces.
const RefPrefix = "npmrc_"

// VarPrefix starts the environment variable that stands in for the value.
const VarPrefix = "SV_"

// authKey matches the key of a line that holds a registry credential.
//
// The three names are the ones npm itself uses. A key may carry a registry
// prefix, as in //registry.npmjs.org/:_authToken. The set is small on purpose:
// a rule that fires on an ordinary setting would rewrite a line that npm needs
// to read as it stands.
var authKey = regexp.MustCompile(`(?i)^(//[^\s=]*:)?_(authToken|auth|password)$`)

// plainToken matches a value that both readers agree on. It has no space, no
// quote and no comment character.
var plainToken = regexp.MustCompile(`^[^\s"'#;]+$`)

// markerPattern finds a marker that a rewrite left behind.
var markerPattern = regexp.MustCompile(`\$\{(` + VarPrefix + `[A-Z0-9_]+)\}`)

// varReference matches any value that npm would expand from the environment.
// Such a value holds no secret, whoever wrote it.
var varReference = regexp.MustCompile(`\$\{[A-Za-z_][A-Za-z0-9_]*\}`)

// Line is one physical line of the file.
type Line struct {
	// Raw is the exact original text, including the line ending.
	Raw string
	// Key is the setting name, empty when the line is not an assignment.
	Key string
	// Value is the text after the equals sign, without the padding and
	// without any trailing comment.
	Value string

	// prefix is everything up to and including the padding after the equals
	// sign. suffix is the trailing whitespace and any trailing comment.
	prefix  string
	suffix  string
	lineEnd string

	dirty bool
	// origValue is what the file said. A line set back to it is written from
	// Raw again, so a value that goes away and comes back leaves no trace.
	origValue string
}

// IsCredential reports whether this line holds a registry credential that this
// package can rewrite.
//
// A value that is already a variable reference is not a credential. init has to
// be safe to run twice, and the second run reads a file this tool rewrote. It
// also has to leave alone the project that already writes ${NPM_TOKEN} by hand,
// because that value is not a secret and there is nothing to move.
func (l *Line) IsCredential() bool {
	if l.Key == "" || l.Value == "" {
		return false
	}
	if !authKey.MatchString(l.Key) || !plainToken.MatchString(l.Value) {
		return false
	}
	return !varReference.MatchString(l.Value)
}

// IsRewritten reports whether the value is a marker this tool wrote.
func (l *Line) IsRewritten() bool { return markerPattern.MatchString(l.Value) }

// Set replaces the value of this one line.
//
// It renders the new line and reads it back before it accepts the change. A
// change that does not read back as the same value is refused. This makes the
// guarantee structural instead of a list of special cases, and it caught two
// real faults: a value written next to a trailing comment merged with it, and
// a value with a space in it read back as a shorter value.
//
// Work on one line and never on a key. An .npmrc file may name the same key
// twice, and a rewrite that went to the wrong line would leave the live token
// on disk while reporting success.
func (l *Line) Set(value string) bool {
	if !plainToken.MatchString(value) {
		return false
	}
	check, next := scanLine(l.prefix+value+l.suffix+l.lineEnd, 0)
	if next != len(l.prefix)+len(value)+len(l.suffix)+len(l.lineEnd) {
		return false
	}
	if check.Key != l.Key || check.Value != value {
		return false
	}
	l.Value = value
	l.dirty = true
	return true
}

// File is a parsed .npmrc file.
type File struct {
	Lines []Line
}

// Parse reads an .npmrc file. It never fails: a line it cannot read keeps its
// text and survives a rewrite unchanged.
func Parse(src []byte) *File {
	f := &File{}
	s := string(src)
	for pos := 0; pos < len(s); {
		line, next := scanLine(s, pos)
		f.Lines = append(f.Lines, line)
		pos = next
	}
	return f
}

// Bytes renders the file. It equals the input when no line changed.
func (f *File) Bytes() []byte {
	var b strings.Builder
	for i := range f.Lines {
		l := &f.Lines[i]
		if l.dirty && l.Value != l.origValue {
			b.WriteString(l.prefix)
			b.WriteString(l.Value)
			b.WriteString(l.suffix)
			b.WriteString(l.lineEnd)
			continue
		}
		b.WriteString(l.Raw)
	}
	return []byte(b.String())
}

// Credentials returns every line that holds a registry credential.
func (f *File) Credentials() []*Line {
	var out []*Line
	for i := range f.Lines {
		if f.Lines[i].IsCredential() {
			out = append(out, &f.Lines[i])
		}
	}
	return out
}

// Assignments returns every line that has a key.
func (f *File) Assignments() []*Line {
	var out []*Line
	for i := range f.Lines {
		if f.Lines[i].Key != "" {
			out = append(out, &f.Lines[i])
		}
	}
	return out
}

// Get returns the value of a key. The last assignment wins, which is what npm
// does.
func (f *File) Get(key string) (string, bool) {
	value, found := "", false
	for i := range f.Lines {
		if f.Lines[i].Key == key {
			value, found = f.Lines[i].Value, true
		}
	}
	return value, found
}

// Set replaces the value of the last assignment of a key, which is the one npm
// reads. Use Line.Set to reach one specific line.
func (f *File) Set(key, value string) bool {
	index := -1
	for i := range f.Lines {
		if f.Lines[i].Key == key {
			index = i
		}
	}
	if index < 0 {
		return false
	}
	return f.Lines[index].Set(value)
}

// scanLine reads one physical line. An .npmrc value never spans two lines,
// which is what lets this parser stay as short as it is.
func scanLine(s string, start int) (Line, int) {
	contentEnd, next, ending := physLine(s, start)
	content := s[start:contentEnd]
	l := Line{Raw: s[start:next], lineEnd: ending}

	trimmed := strings.TrimLeft(content, " \t")
	if trimmed == "" || trimmed[0] == '#' || trimmed[0] == ';' {
		return l, next
	}

	rel := strings.IndexByte(content, '=')
	if rel < 0 {
		return l, next
	}
	key := strings.TrimSpace(content[:rel])
	if key == "" {
		return l, next
	}

	rest := content[rel+1:]
	pad := rest[:len(rest)-len(strings.TrimLeft(rest, " \t"))]
	body := rest[len(pad):]

	// A trailing comment starts at a # or a ; that follows whitespace. A value
	// that holds one of those characters is not a plain token, so it is never
	// rewritten and the split does not matter for it.
	cut := len(body)
	for i := 0; i < len(body); i++ {
		if (body[i] == '#' || body[i] == ';') && (i == 0 || body[i-1] == ' ' || body[i-1] == '\t') {
			cut = i
			break
		}
	}
	value := strings.TrimRight(body[:cut], " \t")

	l.Key = key
	l.Value = value
	l.origValue = value
	l.prefix = content[:rel+1] + pad
	l.suffix = body[len(value):]
	return l, next
}

// physLine finds the end of one physical line.
func physLine(s string, from int) (contentEnd, next int, ending string) {
	i := strings.IndexByte(s[from:], '\n')
	if i < 0 {
		return len(s), len(s), ""
	}
	i += from
	if i > from && s[i-1] == '\r' {
		return i - 1, i + 1, "\r\n"
	}
	return i, i + 1, "\n"
}

// Ref turns an .npmrc key into a canonical store reference.
//
// The result holds only lowercase letters, digits and the underscore, because
// Var turns it into an environment variable name and npm expands it with a
// shell-shaped name. A dot or a dash would not survive that trip.
func Ref(key string) string {
	var b strings.Builder
	b.WriteString(RefPrefix)
	last := byte('_')
	lower := strings.ToLower(key)
	for i := 0; i < len(lower); i++ {
		c := lower[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			b.WriteByte(c)
			last = c
		default:
			if last != '_' {
				b.WriteByte('_')
				last = '_'
			}
		}
	}
	return strings.TrimRight(b.String(), "_")
}

// Var returns the environment variable name that stands in for a reference.
func Var(ref string) string { return VarPrefix + strings.ToUpper(ref) }

// RefFromVar returns the reference behind a variable name, and false when the
// name is not one of ours.
func RefFromVar(name string) (string, bool) {
	if !strings.HasPrefix(name, VarPrefix) {
		return "", false
	}
	ref := strings.ToLower(strings.TrimPrefix(name, VarPrefix))
	if !strings.HasPrefix(ref, RefPrefix) {
		return "", false
	}
	return ref, true
}

// Marker returns the text that replaces a value in the file.
func Marker(ref string) string { return "${" + Var(ref) + "}" }

// Markers returns every reference named by a marker in a text.
func Markers(text string) []string {
	m := markerPattern.FindAllStringSubmatch(text, -1)
	out := make([]string, 0, len(m))
	seen := map[string]bool{}
	for _, g := range m {
		ref, ok := RefFromVar(g[1])
		if !ok || seen[ref] {
			continue
		}
		seen[ref] = true
		out = append(out, ref)
	}
	return out
}

// Package envfile parses and rewrites a .env file without loss.
//
// The contract is absolute: if no line is marked dirty, Bytes returns exactly
// the bytes that Parse received. A clean line is written back from its original
// text and is never rebuilt. Only a dirty line is rendered from its fields.
//
// This module can destroy a developer's file, so every change here needs the
// round-trip fuzz target to stay green.
package envfile

import (
	"strings"
)

// Kind describes what a record holds.
type Kind int

const (
	// Blank is an empty line, or a line of whitespace.
	Blank Kind = iota
	// Comment is a line whose first non-space character is '#'.
	Comment
	// Assignment is a KEY=VALUE record. It may span several physical lines.
	Assignment
	// Other is a line that is none of the above. It is kept and never touched.
	Other
)

const bom = "\ufeff"

// Line is one record. An assignment with a multi-line quoted value is still
// one Line, and Raw then holds every physical line of that value.
type Line struct {
	// Raw holds the exact original text, including the line ending.
	Raw string
	// Kind says how to read the other fields.
	Kind Kind
	// Indent holds the whitespace before the first real character.
	Indent string
	// Export is true when the record starts with "export ".
	Export bool
	// Key is the variable name.
	Key string
	// Value is the decoded value. Escapes are resolved and quotes are removed.
	Value string
	// Quote is 0, '\'' or '"'.
	Quote byte
	// Pad holds the whitespace between '=' and the value.
	Pad string
	// Inline holds the trailing whitespace and any trailing comment.
	Inline string
	// LineEnd is "\n", "\r\n" or "" at the end of a file.
	LineEnd string

	dirty bool
	// origValue and origInline hold what the file said when it was parsed. A
	// line that is set back to these is written from Raw again, so a value
	// that goes away and comes back leaves no trace in the file.
	//
	// This matters because encoding a value is not unique. A newline inside a
	// double quoted value can be a real newline or the two characters \n, and
	// both read back the same. Only the original bytes give an empty diff.
	origValue  string
	origInline string
}

// unchanged reports whether a line still says what the file said.
func (l *Line) unchanged() bool {
	return l.Value == l.origValue && l.Inline == l.origInline
}

// File is a parsed .env file.
type File struct {
	// BOM holds a byte order mark when the file starts with one.
	BOM   string
	Lines []Line
}

// Parse reads a .env file. It never fails on malformed input: a line it cannot
// read becomes Other and survives a rewrite unchanged.
func Parse(src []byte) *File {
	f := &File{}
	s := string(src)
	if strings.HasPrefix(s, bom) {
		f.BOM = bom
		s = s[len(bom):]
	}
	for pos := 0; pos < len(s); {
		line, next := scanRecord(s, pos)
		f.Lines = append(f.Lines, line)
		pos = next
	}
	return f
}

// Bytes renders the file. It equals the input when no line is dirty.
func (f *File) Bytes() []byte {
	var b strings.Builder
	b.WriteString(f.BOM)
	for i := range f.Lines {
		if f.Lines[i].dirty && !f.Lines[i].unchanged() {
			b.WriteString(f.Lines[i].render())
			continue
		}
		b.WriteString(f.Lines[i].Raw)
	}
	return []byte(b.String())
}

// Get returns the value of a key. The last assignment wins, which is what a
// loader does.
func (f *File) Get(key string) (string, bool) {
	value, found := "", false
	for i := range f.Lines {
		if f.Lines[i].Kind == Assignment && f.Lines[i].Key == key {
			value, found = f.Lines[i].Value, true
		}
	}
	return value, found
}

// Set replaces the value of one record and marks it dirty. It returns false
// when the record is not an assignment.
//
// This is the safe way to write. A file may name the same key twice, and only
// the record says which of the two values sits on which line.
func (l *Line) Set(value string) bool {
	if l.Kind != Assignment {
		return false
	}
	l.Value = value
	// The original quote style is kept, which keeps the diff small. encode
	// changes the style by itself when the new value cannot survive it.
	l.dirty = true
	return true
}

// SetInline replaces the trailing comment of one record. An empty comment
// removes it.
func (l *Line) SetInline(comment string) bool {
	if l.Kind != Assignment {
		return false
	}
	if comment == "" {
		l.Inline = ""
	} else {
		l.Inline = "    # " + comment
	}
	l.dirty = true
	return true
}

// Set replaces the value of the last assignment of a key and marks it dirty.
//
// Careful: a file may name the same key twice, and this writes only the last
// of them. A caller that must reach every record uses Assignments and Line.Set
// instead. Writing by key here once left the first of two secret values in the
// clear, because the rewrite touched the last record twice.
func (f *File) Set(key, value string) bool {
	line := f.last(key)
	if line == nil {
		return false
	}
	return line.Set(value)
}

// SetInline replaces the trailing comment of a key. An empty comment removes it.
//
// The warning on Set applies here as well.
func (f *File) SetInline(key, comment string) bool {
	line := f.last(key)
	if line == nil {
		return false
	}
	return line.SetInline(comment)
}

// last returns the last assignment of a key, or nil.
func (f *File) last(key string) *Line {
	var out *Line
	for i := range f.Lines {
		if f.Lines[i].Kind == Assignment && f.Lines[i].Key == key {
			out = &f.Lines[i]
		}
	}
	return out
}

// PhysicalLine returns the 1-based line of the file where a record starts. A
// record with a multi-line quoted value covers more than one physical line, so
// the index of a record is not the number a person reads in an editor.
func (f *File) PhysicalLine(index int) int {
	n := 1
	for i := 0; i < index && i < len(f.Lines); i++ {
		n += strings.Count(f.Lines[i].Raw, "\n")
	}
	return n
}

// Assignments returns every assignment record, in file order.
func (f *File) Assignments() []*Line {
	var out []*Line
	for i := range f.Lines {
		if f.Lines[i].Kind == Assignment {
			out = append(out, &f.Lines[i])
		}
	}
	return out
}

func (l *Line) render() string {
	var b strings.Builder
	b.WriteString(l.Indent)
	if l.Export {
		b.WriteString("export ")
	}
	b.WriteString(l.Key)
	b.WriteString("=")
	b.WriteString(l.Pad)
	b.WriteString(encode(l.Value, l.Quote))
	b.WriteString(l.Inline)
	b.WriteString(l.LineEnd)
	return b.String()
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

func scanRecord(s string, start int) (Line, int) {
	contentEnd, next, ending := physLine(s, start)
	content := s[start:contentEnd]
	trimmed := strings.TrimLeft(content, " \t")
	indent := content[:len(content)-len(trimmed)]

	if trimmed == "" {
		return Line{Raw: s[start:next], Kind: Blank, Indent: indent, LineEnd: ending}, next
	}
	if trimmed[0] == '#' {
		return Line{Raw: s[start:next], Kind: Comment, Indent: indent, LineEnd: ending}, next
	}

	other := func() (Line, int) {
		return Line{Raw: s[start:next], Kind: Other, Indent: indent, LineEnd: ending}, next
	}

	p := start + len(indent)
	export := false
	if strings.HasPrefix(s[p:contentEnd], "export") {
		q := p + len("export")
		for q < contentEnd && (s[q] == ' ' || s[q] == '\t') {
			q++
		}
		if q > p+len("export") {
			export = true
			p = q
		}
	}

	rel := strings.IndexByte(s[p:contentEnd], '=')
	if rel < 0 {
		return other()
	}
	eq := p + rel
	key := strings.TrimRight(s[p:eq], " \t")
	if !validKey(key) {
		return other()
	}

	v := eq + 1
	for v < contentEnd && (s[v] == ' ' || s[v] == '\t') {
		v++
	}
	pad := s[eq+1 : v]

	if v < contentEnd && (s[v] == '"' || s[v] == '\'') {
		quote := s[v]
		if close := findClose(s, v+1, quote); close >= 0 {
			raw := s[v+1 : close]
			ce2, next2, ending2 := physLine(s, close+1)
			return Line{
				Raw:        s[start:next2],
				Kind:       Assignment,
				Indent:     indent,
				Export:     export,
				Key:        key,
				Value:      decode(raw, quote),
				Quote:      quote,
				Pad:        pad,
				Inline:     s[close+1 : ce2],
				LineEnd:    ending2,
				origValue:  decode(raw, quote),
				origInline: s[close+1 : ce2],
			}, next2
		}
		// The quote never closes. Do not swallow the rest of the file. Fall
		// through and read this physical line as an unquoted value.
	}

	raw := s[v:contentEnd]
	cut := len(raw)
	for i := 0; i < len(raw); i++ {
		if raw[i] == '#' && (i == 0 || raw[i-1] == ' ' || raw[i-1] == '\t') {
			cut = i
			break
		}
	}
	value := strings.TrimRight(raw[:cut], " \t")
	return Line{
		Raw:        s[start:next],
		Kind:       Assignment,
		Indent:     indent,
		Export:     export,
		Key:        key,
		Value:      value,
		Quote:      0,
		Pad:        pad,
		Inline:     raw[len(value):],
		LineEnd:    ending,
		origValue:  value,
		origInline: raw[len(value):],
	}, next
}

// findClose returns the index of the closing quote, or -1. A double quote may
// be escaped with a backslash. A single quote may not, which matches dotenv.
func findClose(s string, from int, quote byte) int {
	for i := from; i < len(s); i++ {
		if quote == '"' && s[i] == '\\' {
			i++
			continue
		}
		if s[i] == quote {
			return i
		}
	}
	return -1
}

func validKey(key string) bool {
	if key == "" {
		return false
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c == '_':
		case i > 0 && (c >= '0' && c <= '9' || c == '.' || c == '-'):
		default:
			return false
		}
	}
	return true
}

func decode(raw string, quote byte) string {
	if quote != '"' {
		return raw
	}
	var b strings.Builder
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' || i+1 >= len(raw) {
			b.WriteByte(raw[i])
			continue
		}
		i++
		switch raw[i] {
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case '\\':
			b.WriteByte('\\')
		case '"':
			b.WriteByte('"')
		default:
			b.WriteByte('\\')
			b.WriteByte(raw[i])
		}
	}
	return b.String()
}

func encode(value string, quote byte) string {
	switch quote {
	case '"':
		return `"` + escapeDouble(value) + `"`
	case '\'':
		if strings.ContainsRune(value, '\'') {
			return `"` + escapeDouble(value) + `"`
		}
		return "'" + value + "'"
	default:
		if needsQuote(value) {
			return `"` + escapeDouble(value) + `"`
		}
		return value
	}
}

// escapeDouble makes a value safe between two double quotes.
//
// A newline and a tab stay as they are, because the parser reads a double
// quoted value across more than one physical line. If the encoder wrote \n
// here, a multi-line value would come back with two characters where the
// original file had one, and the restore command could not give back the same
// bytes. A carriage return is still escaped, because a bare carriage return in
// the middle of a value is easy to confuse with a line ending.
func escapeDouble(value string) string {
	r := strings.NewReplacer(
		`\`, `\\`,
		`"`, `\"`,
		"\r", `\r`,
	)
	return r.Replace(value)
}

func needsQuote(value string) bool {
	if value == "" {
		return false
	}
	if strings.HasPrefix(value, "'") || strings.HasPrefix(value, `"`) {
		return true
	}
	return strings.ContainsAny(value, " \t\n\r\"'#")
}

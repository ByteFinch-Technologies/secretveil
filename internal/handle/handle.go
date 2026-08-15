// Package handle owns the sv:// reference format.
//
// A handle stands in for a secret value inside a .env file. It is short, it
// names the variable, and nobody can attack it offline. Encryption would add
// nothing here, because the source file and the runner sit on the same machine.
package handle

import (
	"regexp"
	"sort"
	"strings"
)

// Scheme is the prefix of every handle.
const Scheme = "sv://"

var refPattern = regexp.MustCompile(`sv://([a-z0-9_.\-]+)`)

// Span marks the part of a value that must be replaced by a handle. A whole
// value uses Start 0 and End len(value). A composite value, for example a
// database URL, uses a span that covers the password only.
type Span struct {
	Start int    `json:"start"`
	End   int    `json:"end"`
	Ref   string `json:"ref"`
}

// Ref turns an environment variable name into a canonical reference.
func Ref(key string) string {
	r := strings.ToLower(key)
	r = strings.Map(func(c rune) rune {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_', c == '.', c == '-':
			return c
		default:
			return '_'
		}
	}, r)
	return strings.Trim(r, "_")
}

// Embed replaces every span in a value with its handle. Spans may arrive in
// any order and must not overlap.
func Embed(value string, spans []Span) string {
	if len(spans) == 0 {
		return value
	}
	ordered := make([]Span, len(spans))
	copy(ordered, spans)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Start > ordered[j].Start })

	out := value
	for _, s := range ordered {
		if s.Start < 0 || s.End > len(out) || s.Start > s.End {
			continue
		}
		out = out[:s.Start] + Scheme + s.Ref + out[s.End:]
	}
	return out
}

// Refs returns every reference found in a text.
func Refs(text string) []string {
	m := refPattern.FindAllStringSubmatch(text, -1)
	out := make([]string, 0, len(m))
	seen := map[string]bool{}
	for _, g := range m {
		if !seen[g[1]] {
			seen[g[1]] = true
			out = append(out, g[1])
		}
	}
	return out
}

// Contains reports whether a text holds at least one handle.
func Contains(text string) bool { return strings.Contains(text, Scheme) }

// Resolve replaces every handle in a text using the lookup function. A
// reference the lookup does not know is left in place, and found is false.
func Resolve(text string, lookup func(ref string) (string, bool)) (out string, missing []string) {
	out = refPattern.ReplaceAllStringFunc(text, func(m string) string {
		ref := m[len(Scheme):]
		if v, ok := lookup(ref); ok {
			return v
		}
		missing = append(missing, ref)
		return m
	})
	return out, missing
}

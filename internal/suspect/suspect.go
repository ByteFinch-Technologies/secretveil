// Package suspect finds a value that no classification rule recognised and
// that still does not read like a setting.
//
// The classifier opens a value it does not recognise. That is deliberate: a
// tool that veils every unknown value hides the log level and the time zone,
// and a tool that does that gets switched off. But an opened value that nobody
// looked at is exactly how a credential reaches an agent, and until now the
// tool printed "open" and the developer had no reason to look again.
//
// So this package makes the unknown visible instead of veiling it. It never
// changes the class of a value. It only says that a person should read this
// row, and why.
//
// It is built for recall and not for precision. A wrong guess here costs one
// line of output that a person reads once. A missed guess costs a credential
// that nobody ever reads. The two costs are not equal, so the rules are not
// symmetrical either.
package suspect

import (
	"strings"

	"github.com/ByteFinch-Technologies/secretveil/internal/shape"
)

// minLen is the shortest value that is worth a second look.
//
// It is below the 20 characters that the entropy rule needs, because this
// package reports and does not veil, so it can afford to look further down.
const minLen = 12

// longLen is the length at which a value that reads as no word is worth
// reporting whatever else it holds.
const longLen = 16

// vendorStarts are the openings of a credential that a vendor issues.
//
// A value that starts this way and that reaches this package has failed its
// own shape rule, which almost always means it is shorter or longer than the
// vendor issues. That is worth saying out loud: the value is either a
// credential that the tool must learn, or a placeholder that somebody left in
// the file. Both need a person.
var vendorStarts = strings.Fields(`
	sk- sk_live_ sk_test_ rk_live_ rk_test_ pk_live_ npm_ xox ghp_ gho_ ghu_
	ghs_ ghr_ github_pat_ glpat- glptt- AKIA ASIA AIza SG. SK shp sq0 key-
	eyJ -----BEGIN
`)

// Reason says why a value is worth a second look, or returns an empty string.
//
// The text it returns never holds any part of the value. The report goes to a
// terminal and into a log, and a report that quotes the value it warns about
// puts that value in one more place.
func Reason(value string) string {
	v := strings.TrimSpace(value)
	if v == "" {
		return ""
	}
	// The vendor test runs first and runs on any length. A truncated key and a
	// placeholder both keep the opening, and both are what a person must see.
	for _, start := range vendorStarts {
		if strings.HasPrefix(v, start) {
			return "it starts the way a credential from a vendor starts"
		}
	}
	if len(v) < minLen {
		return ""
	}
	// A value with a space in it is a sentence, a list or a command line.
	if strings.ContainsAny(v, " \t") {
		return ""
	}
	// An address is what the agent is meant to read. A password inside one is
	// the business of the composite rule, which already ran and already won.
	if strings.Contains(v, "://") {
		return ""
	}
	// A value that is not a token at all holds punctuation that no key holds,
	// or it is digits alone. Both are stated limits of the tool.
	if _, ok := shape.Alphabet(v); !ok {
		return ""
	}
	// A path and a name made of words are what a long setting looks like.
	if shape.ReadsAsWords(v) {
		return ""
	}
	if len(v) >= longLen {
		return "it is long and it reads as no word"
	}
	if mixedCaseWithDigits(v) {
		return "it mixes both letter cases with digits, which a setting rarely does"
	}
	return ""
}

// mixedCaseWithDigits reports whether a value holds a lower case letter, an
// upper case letter and a digit.
//
// This is the test that reaches a short key. A setting of twelve characters is
// almost always one case, and a key of twelve characters is almost always not.
func mixedCaseWithDigits(value string) bool {
	var lower, upper, digit bool
	for i := 0; i < len(value); i++ {
		switch c := value[i]; {
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= '0' && c <= '9':
			digit = true
		}
	}
	return lower && upper && digit
}

package redact

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"sort"
	"strings"
	"unicode/utf16"
)

// DefaultMinLen is the shortest value the filter will remove.
//
// A short value costs more than it protects. If a secret is the three letters
// "abc", then the filter deletes those three letters from every word in the
// output, and the output becomes useless. The build reports each value it
// skipped, so the human can see it and change the secret.
const DefaultMinLen = 6

// Options controls how the needle list is built.
type Options struct {
	// MinLen is the shortest value to remove. Zero means DefaultMinLen.
	MinLen int
	// NoEncodings turns off the encoded forms. Use it only in a test.
	NoEncodings bool
}

// Result is the outcome of a build.
type Result struct {
	Matcher *Matcher
	// Skipped names each reference whose value was too short to remove.
	Skipped []string
	// Count is the number of needles in the matcher, including the encoded
	// forms of each value.
	Count int
}

// Build turns a set of secret values into a matcher.
//
// It adds the encoded forms of each value as well as the value itself, because
// a program often prints a secret after it encodes it. A connection library
// that reports a failed request may print the credential inside a base64
// header, and the raw value never appears in that output.
//
// The forms are base64 in both alphabets, hex in both cases, the URL escapes of
// Go, Python, JavaScript, Java and PHP in both cases, and the JSON string
// escapes of Go, Python, Gson and Jackson.
func Build(values map[string]string, opt Options) Result {
	minLen := opt.MinLen
	if minLen <= 0 {
		minLen = DefaultMinLen
	}

	refs := make([]string, 0, len(values))
	for ref := range values {
		refs = append(refs, ref)
	}
	sort.Strings(refs)

	var needles []Needle
	var skipped []string
	seen := map[string]bool{}

	add := func(pattern, ref string) {
		if pattern == "" || len(pattern) < minLen || seen[pattern] {
			return
		}
		seen[pattern] = true
		needles = append(needles, Needle{Pattern: pattern, Ref: ref})
	}

	for _, ref := range refs {
		v := values[ref]
		if len(v) < minLen {
			if v != "" {
				skipped = append(skipped, ref)
			}
			continue
		}
		add(v, ref)
		for _, form := range lineForms(v, minLen) {
			add(form, ref)
		}
		if opt.NoEncodings {
			continue
		}
		for _, form := range Encodings(v) {
			add(form, ref)
		}
	}

	return Result{Matcher: NewMatcher(needles), Skipped: skipped, Count: len(needles)}
}

// Encodings returns the encoded forms of a value that a program may print. It
// does not return the value itself.
func Encodings(v string) []string {
	var out []string
	seen := map[string]bool{v: true}
	keep := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}

	for _, b := range base64Parts(v) {
		keep(b)
	}
	// Each language escapes a different set of characters in a URL, and a
	// percent escape is "%2F" in Go but "%2f" in some other encoders. Each
	// form is different bytes, so the filter needs each of them.
	for _, e := range percentForms(v) {
		keep(e)
		keep(lowerPercent(e))
	}
	// A JSON string for the same value can also be different bytes. See
	// jsonForms. PHP and some other encoders write "/" as "\/".
	for _, j := range jsonForms(v) {
		keep(j)
		keep(strings.ReplaceAll(j, "/", `\/`))
	}
	// Hex needs no shift. Each byte becomes two characters on its own, so the
	// hex of a value is always inside the hex of anything that holds it.
	h := hex.EncodeToString([]byte(v))
	keep(h)
	keep(strings.ToUpper(h))
	return out
}

// lowerPercent returns s with the two hex digits of each percent escape in
// lower case.
func lowerPercent(s string) string {
	b := []byte(s)
	for i := 0; i+2 < len(b); i++ {
		if b[i] == '%' {
			b[i+1] = lowerHex(b[i+1])
			b[i+2] = lowerHex(b[i+2])
			i += 2
		}
	}
	return string(b)
}

func lowerHex(c byte) byte {
	if c >= 'A' && c <= 'F' {
		return c + ('a' - 'A')
	}
	return c
}

// percentSafe holds, for each encoder, the characters other than letters and
// digits that it does not escape. The value of a secret can go into a URL
// through any of them.
var percentSafe = []string{
	// RFC 3986, Python quote(safe="") and quote_plus, PHP rawurlencode.
	"-._~",
	// Python quote with its default, which keeps "/".
	"-._~/",
	// JavaScript encodeURIComponent.
	"-._~!*'()",
	// JavaScript encodeURI.
	"-._~!*'();/?:@&=+$,#",
	// Java URLEncoder and PHP urlencode, which escape "~".
	"-._*",
	"-._",
}

// percentForms returns the URL escapes of v. Each form in percentSafe comes
// with the space as "%20" and as "+", and Go's own two escapes are here too.
// The hex digits are in upper case. Encodings adds the lower case.
func percentForms(v string) []string {
	out := []string{url.QueryEscape(v), url.PathEscape(v)}
	for _, safe := range percentSafe {
		out = append(out, percentEscape(v, safe, "%20"))
		if strings.Contains(v, " ") && !strings.Contains(safe, "+") {
			out = append(out, percentEscape(v, safe, "+"))
		}
	}
	return out
}

// percentEscape escapes each byte of v that is not a letter, a digit or in
// safe. It writes a space as the text in space, which is "%20" or "+".
func percentEscape(v, safe, space string) string {
	const digits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			b.WriteByte(c)
		case c == ' ':
			b.WriteString(space)
		case c < 0x80 && strings.IndexByte(safe, c) >= 0:
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(digits[c>>4])
			b.WriteByte(digits[c&15])
		}
	}
	return b.String()
}

// jsonForms returns the body of each JSON string for v that a common encoder
// writes, with no quotes.
//
// The encoders differ in three ways:
//
//   - Go escapes "<", ">" and "&". Gson also escapes "=" and "'". Python and
//     most other encoders escape none of them.
//   - Python json.dumps writes each character outside ASCII as \uXXXX, and so
//     does Jackson with ESCAPE_NON_ASCII. Go writes the character itself.
//   - The hex digits of \uXXXX are in lower case in Go, Python and Gson, and
//     in upper case in Jackson.
//
// Encodings adds the form of each with "/" written as "\/".
func jsonForms(v string) []string {
	var out []string
	for _, escapeHTML := range []bool{true, false} {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(escapeHTML)
		if err := enc.Encode(v); err != nil {
			continue
		}
		j := strings.TrimSuffix(buf.String(), "\n")
		if len(j) >= 2 {
			out = append(out, j[1:len(j)-1])
		}
	}
	for _, set := range []string{"", "<>&", "<>&='"} {
		for _, ascii := range []bool{false, true} {
			for _, digits := range []string{"0123456789abcdef", "0123456789ABCDEF"} {
				out = append(out, jsonEscape(v, set, ascii, digits))
			}
		}
	}
	return out
}

// jsonEscape writes v as the body of a JSON string. It writes each character
// in set, and each character outside ASCII when ascii is true, as \uXXXX with
// the given hex digits. A character above U+FFFF becomes two \uXXXX escapes,
// as JSON requires.
func jsonEscape(v, set string, ascii bool, digits string) string {
	var b strings.Builder
	u := func(r rune) {
		b.WriteString(`\u`)
		for shift := 12; shift >= 0; shift -= 4 {
			b.WriteByte(digits[(r>>shift)&15])
		}
	}
	for _, r := range v {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r < 0x20:
			u(r)
		case r < 0x80 && strings.ContainsRune(set, r):
			u(r)
		case r >= 0x80 && ascii:
			if r > 0xFFFF {
				r1, r2 := utf16.EncodeRune(r)
				u(r1)
				u(r2)
			} else {
				u(r)
			}
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// lineForms returns the extra needles for a value that holds a newline, such
// as a PEM private key. It returns nothing for a value on one line.
//
// Two forms are needed.
//
// The first is the value as a terminal prints it. The terminal driver turns
// each "\n" into "\r\n" (the ONLCR flag), so the bytes on a pseudo terminal
// are not the bytes of the value, and the value itself never matches there.
//
// The second is each line on its own. A program can print the body of a key
// without its first and last line, and the body is the secret. A line shorter
// than minLen is left out for the same reason a short value is. A PEM armour
// line such as "-----BEGIN PRIVATE KEY-----" is left out as well, because it
// is public text that appears in output that holds no secret.
func lineForms(v string, minLen int) []string {
	if !strings.Contains(v, "\n") {
		return nil
	}
	out := []string{strings.ReplaceAll(v, "\n", "\r\n")}
	for _, line := range strings.Split(v, "\n") {
		line = strings.TrimSpace(line)
		if len(line) < minLen || isArmour(line) {
			continue
		}
		out = append(out, line)
	}
	return out
}

// isArmour reports whether a line is a PEM boundary line.
func isArmour(line string) bool {
	return strings.HasPrefix(line, "-----BEGIN ") || strings.HasPrefix(line, "-----END ")
}

// base64Parts returns the part of the base64 text that holds the value, for
// each alphabet and for each of the three ways the value can sit in the byte
// stream.
//
// Two alphabets are in use. The standard one ends in "+/". The URL one ends in
// "-_", and that is the one a JWT uses, and the one that Python
// urlsafe_b64encode and Node base64url produce. A value encoded with the URL
// alphabet used to pass the filter untouched.
func base64Parts(v string) []string {
	var out []string
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
		out = append(out, base64PartsIn(v, enc)...)
	}
	return out
}

// base64PartsIn returns the stable middle part of each of the three shifts, in
// one alphabet.
//
// A value inside a larger base64 block does not encode to the same characters
// as the value on its own. The characters depend on how many bytes come before
// it. There are three cases, and this returns the stable middle part of each
// one. The first and the last characters are dropped, because they mix the
// value with the bytes around it.
func base64PartsIn(v string, enc *base64.Encoding) []string {
	var out []string
	for shift := 0; shift < 3; shift++ {
		total := shift + len(v)
		full := total / 3 * 3
		end := full / 3 * 4
		// The leading pad bytes reach this many characters.
		start := (shift*4 + 2) / 3
		if end <= start {
			continue
		}
		text := enc.EncodeToString([]byte(strings.Repeat("\x00", shift) + v))
		if end > len(text) {
			continue
		}
		out = append(out, text[start:end])
	}
	return out
}

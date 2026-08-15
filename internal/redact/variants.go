package redact

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"sort"
	"strings"
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
	keep(url.QueryEscape(v))
	keep(url.PathEscape(v))
	if j, err := json.Marshal(v); err == nil && len(j) >= 2 {
		keep(string(j[1 : len(j)-1]))
	}
	return out
}

// base64Parts returns the part of the base64 text that holds the value, for
// each of the three ways the value can sit in the byte stream.
//
// A value inside a larger base64 block does not encode to the same characters
// as the value on its own. The characters depend on how many bytes come before
// it. There are three cases, and this returns the stable middle part of each
// one. The first and the last characters are dropped, because they mix the
// value with the bytes around it.
func base64Parts(v string) []string {
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
		enc := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("\x00", shift) + v))
		if end > len(enc) {
			continue
		}
		out = append(out, enc[start:end])
	}
	return out
}

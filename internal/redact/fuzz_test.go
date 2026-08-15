package redact

import (
	"bytes"
	"strings"
	"testing"
)

// run feeds the input through a filter in pieces of the given size.
func run(m *Matcher, input string, size int) string {
	return runWith(m, input, size, nil)
}

// runWith is run with a choice of placeholder text.
func runWith(m *Matcher, input string, size int, place func(Needle) string) string {
	var out bytes.Buffer
	w := NewWriter(&out, m)
	w.Placeholder = place
	if size < 1 {
		size = 1
	}
	for i := 0; i < len(input); i += size {
		j := i + size
		if j > len(input) {
			j = len(input)
		}
		_, _ = w.Write([]byte(input[i:j]))
	}
	_ = w.Close()
	return out.String()
}

// needlesFrom turns three fuzz strings into a needle set. It drops a needle
// that is too short, because the filter drops it too.
func needlesFrom(a, b, c string) []Needle {
	var out []Needle
	for i, p := range []string{a, b, c} {
		if len(p) < 2 {
			continue
		}
		out = append(out, Needle{Pattern: p, Ref: string(rune('a' + i))})
	}
	return out
}

// mark is the placeholder that the two invariant tests use. It is one byte, and
// each test skips an input or a needle that holds that byte. A placeholder that
// no needle can contain makes the search for a survivor exact.
const mark = "\x01"

// clean reports whether every one of these strings is free of the placeholder
// byte.
func clean(ss ...string) bool {
	for _, s := range ss {
		if strings.Contains(s, mark) {
			return false
		}
	}
	return true
}

// marked returns the placeholder for every needle.
func marked(Needle) string { return mark }

// collapse replaces each run of placeholders with a single placeholder.
//
// Two placeholders that touch each other say the same thing as one, and the
// filter may split one into two. FuzzIdleFlushIsInvariant says why.
func collapse(s string) string {
	for strings.Contains(s, mark+mark) {
		s = strings.ReplaceAll(s, mark+mark, mark)
	}
	return s
}

// FuzzNoNeedleSurvives is the safety property. Whatever the input and whatever
// the piece size, no needle survives in the bytes that the filter lets through.
//
// The placeholder has to be chosen with care, and the first version of this test
// got it wrong twice.
//
// A placeholder is text that the filter writes itself. If it ends with the first
// characters of a needle, the rest of the needle can follow in the normal output,
// and a plain search finds the needle across a join that no secret ever crossed.
// The first version answered that with an empty placeholder, so that the output
// held only bytes that came from the input.
//
// That answer is wrong, because removal makes a join of its own. Take the needle
// "10" and the input "1100". The filter removes the needle at position 1, the
// remaining "1" and "0" become neighbours, and the search reports a survivor.
// Neither byte was ever part of a secret. The real placeholder is "sv://" and a
// reference name, so it always writes at least five bytes and two bytes of the
// input can never meet.
//
// The answer used here is a placeholder of one byte that no needle may contain.
// It keeps the two input bytes apart, and it cannot help to build a needle. Any
// needle found in the output is then a real survivor.
func FuzzNoNeedleSurvives(f *testing.F) {
	f.Add("before tr0ub4dor after", "tr0ub4dor", "", "", 3)
	f.Add("aaaa", "aa", "aaa", "", 1)
	f.Add("abcabcabc", "abc", "bca", "cab", 2)
	f.Add("", "x", "", "", 1)
	f.Add("\x00\x00\x00", "\x00\x00", "", "", 1)
	f.Add("1100", "10", "", "", 1)

	f.Fuzz(func(t *testing.T, input, n1, n2, n3 string, size int) {
		if !clean(input, n1, n2, n3) {
			return
		}
		needles := needlesFrom(n1, n2, n3)
		if len(needles) == 0 {
			return
		}
		m := NewMatcher(needles)
		out := runWith(m, input, size%64, marked)
		for _, n := range needles {
			if strings.Contains(out, n.Pattern) {
				t.Fatalf("the needle %q survived in %q (input %q, size %d)",
					n.Pattern, out, input, size%64)
			}
		}
	})
}

// FuzzChunkingIsInvariant is the correctness property. The result must not
// depend on how the input was cut into writes. This is what finds a fault in
// the hold back window, because a fault there changes the output for one piece
// size and not for another.
func FuzzChunkingIsInvariant(f *testing.F) {
	f.Add("before tr0ub4dor after", "tr0ub4dor", "", "")
	f.Add("xxSECRETyy", "SECRET", "ETy", "")
	f.Add("abcdefghij", "abcdef", "defghij", "cde")
	f.Add("aaaaaaaaaa", "aaa", "aa", "")

	f.Fuzz(func(t *testing.T, input, n1, n2, n3 string) {
		needles := needlesFrom(n1, n2, n3)
		if len(needles) == 0 {
			return
		}
		m := NewMatcher(needles)
		want := run(m, input, len(input)+1)
		for _, size := range []int{1, 2, 3, 5, 7, 13} {
			if got := run(m, input, size); got != want {
				t.Fatalf("piece size %d changed the result.\ninput %q\nwhole %q\npieces %q",
					size, input, want, got)
			}
		}
	})
}

// FuzzIdleFlushIsInvariant proves an idle flush between two writes does not
// let a byte of a secret out, and does not move any other byte. A filter that
// releases a partial match on the timer fails here.
//
// The test compares the two results after each run of placeholders is reduced to
// one placeholder. An idle flush is allowed to change the number of placeholders,
// and only that.
//
// The reason is the rule in idleLimit. While the stream is quiet, a run of bytes
// that a needle already covers goes out at once, so a prompt that ends with a
// secret still reaches the terminal. That run can still grow when the next byte
// arrives, and the part that is already out cannot be taken back. The filter
// writes a second placeholder beside the first.
//
// One needle "aa" and the input "0aaaaa" show it. With no flush the output is
// four placeholders, and with a flush after "0aaa" it is three. No byte of the
// input reaches the output in either case, which is the property that matters.
// This is why the check is written on the reduced form and not on the exact text.
func FuzzIdleFlushIsInvariant(f *testing.F) {
	f.Add("before tr0ub4dor after", "tr0ub4dor", 7)
	f.Add("xxSECRETyy", "SECRET", 3)
	f.Add("aaaaaa", "aaa", 2)
	f.Add("0aaaaa", "aa", 4)

	f.Fuzz(func(t *testing.T, input, needle string, cut int) {
		if len(needle) < 2 || len(input) == 0 || !clean(input, needle) {
			return
		}
		m := NewMatcher([]Needle{{Pattern: needle, Ref: "a"}})
		want := runWith(m, input, len(input)+1, marked)

		at := cut % (len(input) + 1)
		if at < 0 {
			at += len(input) + 1
		}
		var out bytes.Buffer
		w := NewWriter(&out, m)
		w.Placeholder = marked
		_, _ = w.Write([]byte(input[:at]))
		if err := w.FlushIdle(); err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(input[at:]))
		_ = w.Close()

		got := out.String()
		if strings.Contains(got, needle) {
			t.Fatalf("an idle flush at %d let the needle %q out in %q (input %q)",
				at, needle, got, input)
		}
		if collapse(got) != collapse(want) {
			t.Fatalf("an idle flush at %d moved a byte.\ninput %q\nno flush %q\nwith flush %q",
				at, input, want, got)
		}
	})
}

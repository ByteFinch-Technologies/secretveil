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

// FuzzNoNeedleSurvives is the safety property. Whatever the input and whatever
// the piece size, no needle survives in the bytes that the filter lets through.
//
// The test uses an empty placeholder on purpose. A placeholder is text that the
// filter writes itself, and that text can end with the first characters of a
// needle. The rest of the needle can then follow in the normal output, and a
// plain search finds the needle across a join that no secret ever crossed. That
// is a fault in the search, not a leak. With no placeholder, the output holds
// only the bytes that came from the input, so the search is exact.
//
// The join is still a real limit of the product, because a reference name is
// part of the handle text. It needs a secret that starts with the last
// characters of its own reference name, so it can only happen with a very short
// secret. The adversarial test set records it as a known limit.
func FuzzNoNeedleSurvives(f *testing.F) {
	f.Add("before tr0ub4dor after", "tr0ub4dor", "", "", 3)
	f.Add("aaaa", "aa", "aaa", "", 1)
	f.Add("abcabcabc", "abc", "bca", "cab", 2)
	f.Add("", "x", "", "", 1)
	f.Add("\x00\x00\x00", "\x00\x00", "", "", 1)

	f.Fuzz(func(t *testing.T, input, n1, n2, n3 string, size int) {
		needles := needlesFrom(n1, n2, n3)
		if len(needles) == 0 {
			return
		}
		m := NewMatcher(needles)
		out := runWith(m, input, size%64, func(Needle) string { return "" })
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
// change the result. A filter that releases a partial match on the timer fails
// here.
func FuzzIdleFlushIsInvariant(f *testing.F) {
	f.Add("before tr0ub4dor after", "tr0ub4dor", 7)
	f.Add("xxSECRETyy", "SECRET", 3)
	f.Add("aaaaaa", "aaa", 2)

	f.Fuzz(func(t *testing.T, input, needle string, cut int) {
		if len(needle) < 2 || len(input) == 0 {
			return
		}
		m := NewMatcher([]Needle{{Pattern: needle, Ref: "a"}})
		want := run(m, input, len(input)+1)

		at := cut % (len(input) + 1)
		if at < 0 {
			at += len(input) + 1
		}
		var out bytes.Buffer
		w := NewWriter(&out, m)
		_, _ = w.Write([]byte(input[:at]))
		if err := w.FlushIdle(); err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(input[at:]))
		_ = w.Close()

		if got := out.String(); got != want {
			t.Fatalf("an idle flush at %d changed the result.\ninput %q\nno flush %q\nwith flush %q",
				at, input, want, got)
		}
	})
}

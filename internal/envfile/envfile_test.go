package envfile

import (
	"strings"
	"testing"
)

// The golden corpus. Every entry must round-trip byte for byte.
var corpus = map[string]string{
	"simple":            "KEY=value\n",
	"export":            "export KEY=value\n",
	"export_tab":        "export\tKEY=value\n",
	"key_named_export":  "export=1\n",
	"no_export_space":   "exportKEY=1\n",
	"single_quote":      "KEY='value with space'\n",
	"double_quote":      "KEY=\"value with space\"\n",
	"hash_in_quotes":    "KEY=\"a#b\"\n",
	"hash_no_space":     "KEY=a#b\n",
	"trailing_comment":  "KEY=value # a note\n",
	"comment_only":      "# just a comment\n",
	"indented_comment":  "   # indented\n",
	"blank":             "\n\n\n",
	"whitespace_line":   "   \t\n",
	"crlf":              "KEY=value\r\nOTHER=2\r\n",
	"no_final_newline":  "KEY=value",
	"empty_value":       "KEY=\n",
	"empty_then_note":   "KEY= # note\n",
	"no_equals":         "this is not an assignment\n",
	"url_line":          "https://example.com/path\n",
	"duplicate":         "KEY=first\nKEY=second\n",
	"spaces_around_eq":  "KEY = value\n",
	"trailing_spaces":   "KEY=value   \n",
	"escaped_quote":     "KEY=\"say \\\"hi\\\"\"\n",
	"escaped_newline":   "KEY=\"line1\\nline2\"\n",
	"backslash_literal": "KEY='C:\\\\path'\n",
	"unterminated":      "KEY=\"never closes\nNEXT=2\n",
	"bom":               "\ufeffKEY=value\n",
	"indented_assign":   "    KEY=value\n",
	"multiline_pem": "KEY=\"-----BEGIN PRIVATE KEY-----\n" +
		"MIIEvQIBADANBg\nkqhkiG9w0BAQEF\n" +
		"-----END PRIVATE KEY-----\"\nNEXT=2\n",
	"mixed": "# header\n\nexport A=1\nB='two'\nC=\"three\" # note\n\n# tail\n",
}

func TestRoundTripCorpus(t *testing.T) {
	for name, src := range corpus {
		t.Run(name, func(t *testing.T) {
			got := string(Parse([]byte(src)).Bytes())
			if got != src {
				t.Fatalf("round trip changed the bytes\n want %q\n  got %q", src, got)
			}
		})
	}
}

func TestParseFields(t *testing.T) {
	cases := []struct {
		name   string
		src    string
		key    string
		value  string
		quote  byte
		export bool
		inline string
	}{
		{"simple", "KEY=value\n", "KEY", "value", 0, false, ""},
		{"export", "export KEY=value\n", "KEY", "value", 0, true, ""},
		{"single", "KEY='a b'\n", "KEY", "a b", '\'', false, ""},
		{"double", "KEY=\"a b\"\n", "KEY", "a b", '"', false, ""},
		{"hash_in_quotes", "KEY=\"a#b\"\n", "KEY", "a#b", '"', false, ""},
		{"hash_no_space", "KEY=a#b\n", "KEY", "a#b", 0, false, ""},
		{"trailing_comment", "KEY=v # note\n", "KEY", "v", 0, false, " # note"},
		{"trailing_spaces", "KEY=v   \n", "KEY", "v", 0, false, "   "},
		{"escaped_quote", "KEY=\"say \\\"hi\\\"\"\n", "KEY", `say "hi"`, '"', false, ""},
		{"escaped_newline", "KEY=\"a\\nb\"\n", "KEY", "a\nb", '"', false, ""},
		{"single_no_escape", "KEY='a\\nb'\n", "KEY", `a\nb`, '\'', false, ""},
		{"empty", "KEY=\n", "KEY", "", 0, false, ""},
		{"spaces_around_eq", "KEY = value\n", "KEY", "value", 0, false, ""},
		{"crlf", "KEY=value\r\n", "KEY", "value", 0, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := Parse([]byte(c.src))
			as := f.Assignments()
			if len(as) != 1 {
				t.Fatalf("want 1 assignment, got %d", len(as))
			}
			a := as[0]
			if a.Key != c.key {
				t.Errorf("key: want %q got %q", c.key, a.Key)
			}
			if a.Value != c.value {
				t.Errorf("value: want %q got %q", c.value, a.Value)
			}
			if a.Quote != c.quote {
				t.Errorf("quote: want %q got %q", c.quote, a.Quote)
			}
			if a.Export != c.export {
				t.Errorf("export: want %v got %v", c.export, a.Export)
			}
			if a.Inline != c.inline {
				t.Errorf("inline: want %q got %q", c.inline, a.Inline)
			}
		})
	}
}

func TestNotAssignments(t *testing.T) {
	for _, src := range []string{
		"this is not an assignment\n",
		"https://example.com/path\n",
		"foo bar=baz\n",
		"9KEY=1\n",
	} {
		f := Parse([]byte(src))
		if got := len(f.Assignments()); got != 0 {
			t.Errorf("%q: want 0 assignments, got %d", src, got)
		}
		if string(f.Bytes()) != src {
			t.Errorf("%q: round trip failed", src)
		}
	}
}

func TestMultilineValue(t *testing.T) {
	src := "A=1\nPEM=\"line1\nline2\nline3\"\nB=2\n"
	f := Parse([]byte(src))
	// Three records: A, the multi-line PEM, and B.
	if len(f.Lines) != 3 {
		t.Fatalf("want 3 records, got %d", len(f.Lines))
	}
	v, ok := f.Get("PEM")
	if !ok || v != "line1\nline2\nline3" {
		t.Fatalf("want the three lines, got %q", v)
	}
	if string(f.Bytes()) != src {
		t.Fatal("round trip failed")
	}
}

func TestUnterminatedQuoteDoesNotSwallowFile(t *testing.T) {
	src := "KEY=\"never closes\nNEXT=2\n"
	f := Parse([]byte(src))
	if _, ok := f.Get("NEXT"); !ok {
		t.Fatal("NEXT was swallowed by the unterminated quote")
	}
	if string(f.Bytes()) != src {
		t.Fatal("round trip failed")
	}
}

func TestDuplicateKeyLastWins(t *testing.T) {
	f := Parse([]byte("KEY=first\nKEY=second\n"))
	if v, _ := f.Get("KEY"); v != "second" {
		t.Fatalf("want second, got %q", v)
	}
	f.Set("KEY", "sv://ref")
	if got := string(f.Bytes()); got != "KEY=first\nKEY=sv://ref\n" {
		t.Fatalf("Set touched the wrong line: %q", got)
	}
}

func TestSetOnlyRewritesItsOwnLine(t *testing.T) {
	src := "# header\nexport A = 'one'   # keep me\nB=two\n"
	f := Parse([]byte(src))
	if !f.Set("B", "sv://b") {
		t.Fatal("Set returned false")
	}
	want := "# header\nexport A = 'one'   # keep me\nB=sv://b\n"
	if got := string(f.Bytes()); got != want {
		t.Fatalf("want %q\n got %q", want, got)
	}
}

func TestSetPreservesQuoteStyleAndComment(t *testing.T) {
	f := Parse([]byte("KEY='old value' # note\n"))
	f.Set("KEY", "sv://key")
	want := "KEY='sv://key' # note\n"
	if got := string(f.Bytes()); got != want {
		t.Fatalf("want %q got %q", want, got)
	}
}

func TestSetEscapesWhenNeeded(t *testing.T) {
	f := Parse([]byte("KEY=plain\n"))
	f.Set("KEY", `has "quote" and space`)
	want := "KEY=\"has \\\"quote\\\" and space\"\n"
	if got := string(f.Bytes()); got != want {
		t.Fatalf("want %q got %q", want, got)
	}
	// The rewritten value must parse back to the same string.
	if v, _ := Parse([]byte(want)).Get("KEY"); v != `has "quote" and space` {
		t.Fatalf("re-parse gave %q", v)
	}
}

func TestSetInline(t *testing.T) {
	f := Parse([]byte("KEY=value\n"))
	f.SetInline("KEY", "sv: 40 chars, hex")
	want := "KEY=value    # sv: 40 chars, hex\n"
	if got := string(f.Bytes()); got != want {
		t.Fatalf("want %q got %q", want, got)
	}
}

func TestSetMissingKey(t *testing.T) {
	f := Parse([]byte("KEY=value\n"))
	if f.Set("NOPE", "x") {
		t.Fatal("Set on a missing key must return false")
	}
	if string(f.Bytes()) != "KEY=value\n" {
		t.Fatal("a failed Set changed the file")
	}
}

func TestCRLFPreserved(t *testing.T) {
	f := Parse([]byte("A=1\r\nB=2\r\n"))
	f.Set("A", "sv://a")
	if got := string(f.Bytes()); got != "A=sv://a\r\nB=2\r\n" {
		t.Fatalf("CRLF lost: %q", got)
	}
}

func TestBOMPreserved(t *testing.T) {
	f := Parse([]byte("\ufeffA=1\n"))
	f.Set("A", "sv://a")
	if got := string(f.Bytes()); got != "\ufeffA=sv://a\n" {
		t.Fatalf("BOM lost: %q", got)
	}
}

// FuzzRoundTrip is a release gate. Parse then Bytes must be the identity when
// no line is dirty, for any input at all.
func FuzzRoundTrip(f *testing.F) {
	for _, src := range corpus {
		f.Add([]byte(src))
	}
	f.Add([]byte("KEY=\"\\"))
	f.Add([]byte("=\n"))
	f.Add([]byte("\r\n\r\n"))
	f.Add([]byte("export "))
	f.Fuzz(func(t *testing.T, src []byte) {
		got := Parse(src).Bytes()
		if string(got) != string(src) {
			t.Fatalf("round trip changed the bytes\n want %q\n  got %q", src, got)
		}
	})
}

// FuzzSetReparse checks that a value written by Set reads back unchanged.
func FuzzSetReparse(f *testing.F) {
	f.Add("value")
	f.Add(`has "quote"`)
	f.Add("has space")
	f.Add("a#b")
	f.Add("")
	f.Add("multi\nline")
	f.Add("'single'")
	f.Fuzz(func(t *testing.T, value string) {
		if strings.ContainsAny(value, "\x00") {
			t.Skip()
		}
		file := Parse([]byte("KEY=placeholder\n"))
		if !file.Set("KEY", value) {
			t.Fatal("Set failed")
		}
		back, ok := Parse(file.Bytes()).Get("KEY")
		if !ok {
			t.Fatalf("key vanished after Set(%q) -> %q", value, file.Bytes())
		}
		if back != value {
			t.Fatalf("Set(%q) produced %q which reads back as %q", value, file.Bytes(), back)
		}
	})
}

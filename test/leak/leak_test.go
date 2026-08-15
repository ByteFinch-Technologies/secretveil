// Package leak holds the acceptance harness for the output filter.
//
// The rule for every case is the same. Feed the input through the filter in
// pieces, then check two things:
//
//  1. No secret value survives anywhere in the output.
//  2. Every byte that is not a secret survives unchanged.
//
// The second rule matters as much as the first. A filter that deletes
// everything passes the first rule and is useless.
package leak

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/ByteFinch-Technologies/secretveil/internal/redact"
)

// feed writes the input through a new filter in pieces of the given sizes and
// returns the whole output.
func feed(t *testing.T, values map[string]string, input string, chunk func(string) []string) string {
	t.Helper()
	res := redact.Build(values, redact.Options{MinLen: 4})
	var out bytes.Buffer
	w := redact.NewWriter(&out, res.Matcher)
	for _, piece := range chunk(input) {
		if _, err := w.Write([]byte(piece)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func whole(s string) []string { return []string{s} }

func splitAt(i int) func(string) []string {
	return func(s string) []string {
		if i >= len(s) {
			return []string{s}
		}
		return []string{s[:i], s[i:]}
	}
}

func byteByByte(s string) []string {
	out := make([]string, 0, len(s))
	for i := 0; i < len(s); i++ {
		out = append(out, s[i:i+1])
	}
	return out
}

// mustHide fails when any secret value appears in the output.
func mustHide(t *testing.T, out string, values map[string]string, note string) {
	t.Helper()
	for ref, v := range values {
		if strings.Contains(out, v) {
			t.Errorf("%s: the secret %s survived in the output: %q", note, ref, out)
		}
	}
}

// mustKeep fails when a piece of ordinary text was lost.
func mustKeep(t *testing.T, out string, keep []string, note string) {
	t.Helper()
	for _, k := range keep {
		if !strings.Contains(out, k) {
			t.Errorf("%s: the filter removed ordinary text %q, output was %q", note, k, out)
		}
	}
}

// Case 1. The whole secret arrives in one write.
func TestCase01WholeSecretInOneWrite(t *testing.T) {
	values := map[string]string{"db_password": "tr0ub4dor-horse"}
	input := "connecting with password tr0ub4dor-horse to the database\n"
	out := feed(t, values, input, whole)
	mustHide(t, out, values, "case 1")
	mustKeep(t, out, []string{"connecting with password ", " to the database\n"}, "case 1")
	if !strings.Contains(out, "sv://db_password") {
		t.Errorf("case 1: the placeholder is missing: %q", out)
	}
}

// Case 2. The secret is cut in two by the write boundary.
func TestCase02SecretSplitInTwo(t *testing.T) {
	values := map[string]string{"db_password": "tr0ub4dor-horse"}
	input := "password=tr0ub4dor-horse;"
	out := feed(t, values, input, splitAt(14))
	mustHide(t, out, values, "case 2")
	mustKeep(t, out, []string{"password=", ";"}, "case 2")
}

// Case 3. The secret is cut at every offset. This is the case that finds the
// off by one fault in the hold back window.
func TestCase03SecretSplitAtEveryOffset(t *testing.T) {
	values := map[string]string{"db_password": "tr0ub4dor-horse"}
	input := "before tr0ub4dor-horse after"
	for i := 0; i <= len(input); i++ {
		out := feed(t, values, input, splitAt(i))
		if strings.Contains(out, values["db_password"]) {
			t.Fatalf("case 3: the secret survived when the input was cut at offset %d: %q", i, out)
		}
		if !strings.HasPrefix(out, "before ") || !strings.HasSuffix(out, " after") {
			t.Fatalf("case 3: the ordinary text changed at offset %d: %q", i, out)
		}
	}
}

// Case 4. Every write is one byte. This is the terminal typing case.
func TestCase04OneByteAtATime(t *testing.T) {
	values := map[string]string{"jwt_secret": "aBcDeF1234567890"}
	input := "token: aBcDeF1234567890 end"
	out := feed(t, values, input, byteByByte)
	mustHide(t, out, values, "case 4")
	mustKeep(t, out, []string{"token: ", " end"}, "case 4")
}

// Case 5. Two different secrets sit next to each other with nothing between.
func TestCase05TwoSecretsTouching(t *testing.T) {
	values := map[string]string{
		"first_secret":  "AAAAAAAAAAAA",
		"second_secret": "BBBBBBBBBBBB",
	}
	input := "x" + values["first_secret"] + values["second_secret"] + "y"
	for i := 0; i <= len(input); i++ {
		out := feed(t, values, input, splitAt(i))
		mustHide(t, out, values, "case 5")
		if !strings.HasPrefix(out, "x") || !strings.HasSuffix(out, "y") {
			t.Fatalf("case 5: the ordinary text changed at offset %d: %q", i, out)
		}
	}
}

// Case 6. One secret is a substring of another. The filter must remove both,
// and the longer one must win where they overlap.
func TestCase06OneSecretInsideAnother(t *testing.T) {
	values := map[string]string{
		"short_secret": "abcdefgh",
		"long_secret":  "abcdefghijklmnop",
	}
	for _, input := range []string{
		"value=abcdefgh;",
		"value=abcdefghijklmnop;",
		"a=abcdefgh b=abcdefghijklmnop",
	} {
		for i := 0; i <= len(input); i++ {
			out := feed(t, values, input, splitAt(i))
			if strings.Contains(out, "abcdefgh") {
				t.Fatalf("case 6: a secret survived in %q at offset %d: %q", input, i, out)
			}
		}
	}
}

// Case 7. The same secret appears many times.
func TestCase07SecretRepeated(t *testing.T) {
	values := map[string]string{"api_key": "kQ8vN2xR7mL4pT9w"}
	input := strings.Repeat("key="+values["api_key"]+"\n", 50)
	out := feed(t, values, input, byteByByte)
	mustHide(t, out, values, "case 7")
	if got := strings.Count(out, "sv://api_key"); got != 50 {
		t.Errorf("case 7: want 50 placeholders, got %d", got)
	}
	if got := strings.Count(out, "key="); got != 50 {
		t.Errorf("case 7: the ordinary text was damaged, want 50 copies of key=, got %d", got)
	}
}

// Case 8. The secret sits at the very start and at the very end, with nothing
// around it to give the filter a boundary.
func TestCase08SecretAtBothEnds(t *testing.T) {
	values := map[string]string{"edge_secret": "zZzZzZzZzZzZ"}
	for _, input := range []string{
		values["edge_secret"],
		values["edge_secret"] + " middle " + values["edge_secret"],
		"lead " + values["edge_secret"],
		values["edge_secret"] + " trail",
	} {
		for i := 0; i <= len(input); i++ {
			out := feed(t, values, input, splitAt(i))
			if strings.Contains(out, values["edge_secret"]) {
				t.Fatalf("case 8: the secret survived in %q at offset %d: %q", input, i, out)
			}
		}
	}
}

// Case 9. The program printed the secret inside a base64 block. The raw value
// never appears, so a filter that looks only for the raw value misses it.
func TestCase09Base64EncodedSecret(t *testing.T) {
	secret := "tr0ub4dor-horse-battery"
	values := map[string]string{"db_password": secret}

	// Three cases, one for each way the value can sit in the byte stream.
	for shift := 0; shift < 3; shift++ {
		prefix := strings.Repeat("Q", shift)
		blob := base64.StdEncoding.EncodeToString([]byte(prefix + secret + "tail"))
		input := "Authorization: Basic " + blob + "\n"
		out := feed(t, values, input, whole)
		if strings.Contains(out, blob) {
			t.Errorf("case 9: the base64 form of the secret survived at shift %d: %q", shift, out)
		}
		if !strings.Contains(out, "Authorization: Basic ") {
			t.Errorf("case 9: the ordinary text was lost at shift %d: %q", shift, out)
		}
	}
}

// Case 10. The program printed the secret inside a URL.
func TestCase10URLEncodedSecret(t *testing.T) {
	secret := "p@ssw0rd/with+signs=here"
	values := map[string]string{"db_password": secret}
	encoded := url.QueryEscape(secret)
	if encoded == secret {
		t.Fatal("the test value must change when it is URL encoded")
	}
	input := "GET /login?pw=" + encoded + " HTTP/1.1\n"
	out := feed(t, values, input, byteByByte)
	if strings.Contains(out, encoded) {
		t.Errorf("case 10: the URL encoded secret survived: %q", out)
	}
	mustHide(t, out, values, "case 10")
	mustKeep(t, out, []string{"GET /login?pw=", " HTTP/1.1\n"}, "case 10")
}

// Case 11. The program printed the secret inside a JSON document.
func TestCase11JSONEscapedSecret(t *testing.T) {
	secret := "line1\nline2\"quoted\"\\slash"
	values := map[string]string{"private_key": secret}
	doc, err := json.Marshal(map[string]string{"key": secret})
	if err != nil {
		t.Fatal(err)
	}
	input := "response: " + string(doc) + "\n"
	out := feed(t, values, input, whole)

	escaped, _ := json.Marshal(secret)
	inner := string(escaped[1 : len(escaped)-1])
	if strings.Contains(out, inner) {
		t.Errorf("case 11: the JSON escaped secret survived: %q", out)
	}
	mustHide(t, out, values, "case 11")
	mustKeep(t, out, []string{"response: ", `{"key":`}, "case 11")
}

// Case 12. The stream goes quiet in the middle of a secret. The idle flush
// must not release the part it already holds.
//
// This is the case that a filter with a plain timer gets wrong. It flushes on
// the timer, half of the secret goes out, and the other half follows when the
// stream starts again.
func TestCase12IdleFlushHoldsAPartialSecret(t *testing.T) {
	secret := "tr0ub4dor-horse"
	values := map[string]string{"db_password": secret}
	res := redact.Build(values, redact.Options{MinLen: 4})

	for cut := 1; cut < len(secret); cut++ {
		var out bytes.Buffer
		w := redact.NewWriter(&out, res.Matcher)

		if _, err := w.Write([]byte("prompt: " + secret[:cut])); err != nil {
			t.Fatal(err)
		}
		// The stream is quiet. Release everything that is provably safe.
		if err := w.FlushIdle(); err != nil {
			t.Fatal(err)
		}

		// The check is exact. A "does it contain the prefix" check is wrong
		// here, because a one byte prefix such as "t" also appears in the
		// word "prompt". The rule is that the idle flush releases the
		// ordinary text and nothing else.
		if early := out.String(); early != "prompt: " {
			t.Fatalf("case 12: at cut %d the idle flush must release exactly %q, it released %q",
				cut, "prompt: ", early)
		}

		if _, err := w.Write([]byte(secret[cut:] + " done")); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		final := out.String()
		if strings.Contains(final, secret) {
			t.Fatalf("case 12: the secret survived after the stream started again at cut %d: %q", cut, final)
		}
		if !strings.Contains(final, "sv://db_password") {
			t.Fatalf("case 12: the placeholder is missing at cut %d: %q", cut, final)
		}
	}
}

// ---------------------------------------------------------------- properties

// TestIdleFlushReleasesOrdinaryTextAtOnce is the latency rule. A prompt that
// holds no secret must reach the terminal without waiting.
func TestIdleFlushReleasesOrdinaryTextAtOnce(t *testing.T) {
	values := map[string]string{"db_password": "tr0ub4dor-horse"}
	res := redact.Build(values, redact.Options{MinLen: 4})
	var out bytes.Buffer
	w := redact.NewWriter(&out, res.Matcher)

	const prompt = "Enter your name: "
	if _, err := w.Write([]byte(prompt)); err != nil {
		t.Fatal(err)
	}
	if err := w.FlushIdle(); err != nil {
		t.Fatal(err)
	}
	if out.String() != prompt {
		t.Errorf("the whole prompt must go out on the idle flush, got %q", out.String())
	}
}

// TestHoldBackIsBounded proves the filter does not grow with the size of the
// stream. It may hold at most twice the longest needle.
func TestHoldBackIsBounded(t *testing.T) {
	longest := strings.Repeat("s", 200)
	values := map[string]string{"long_secret": longest, "short_secret": "abcdefgh"}
	res := redact.Build(values, redact.Options{MinLen: 4})
	w := redact.NewWriter(&bytes.Buffer{}, res.Matcher)

	limit := 2 * res.Matcher.MaxLen()
	for i := 0; i < 2000; i++ {
		if _, err := w.Write([]byte("some ordinary log line number 12345\n")); err != nil {
			t.Fatal(err)
		}
		if held := w.Held(); held > limit {
			t.Fatalf("the filter is holding %d bytes after %d writes, and the limit is %d", held, i, limit)
		}
	}
}

// TestTextWithNoSecretIsUnchanged is the other half of the contract.
func TestTextWithNoSecretIsUnchanged(t *testing.T) {
	values := map[string]string{"db_password": "tr0ub4dor-horse"}
	input := strings.Repeat("the quick brown fox jumps over the lazy dog\n", 100)
	out := feed(t, values, input, byteByByte)
	if out != input {
		t.Error("text with no secret in it must pass through unchanged")
	}
}

// TestShortValueIsReportedNotRemoved states the rule for a value that is too
// short to remove safely.
func TestShortValueIsReportedNotRemoved(t *testing.T) {
	res := redact.Build(map[string]string{"otp_length": "6", "debug_flag": "true"},
		redact.Options{})
	if len(res.Skipped) != 2 {
		t.Fatalf("want both short values reported, got %v", res.Skipped)
	}
	if !res.Matcher.Empty() {
		t.Error("a short value must not become a needle")
	}
}

// TestEmptyMatcherPassesEverythingThrough guards the common case of a project
// with no secret at all.
func TestEmptyMatcherPassesEverythingThrough(t *testing.T) {
	res := redact.Build(map[string]string{}, redact.Options{})
	var out bytes.Buffer
	w := redact.NewWriter(&out, res.Matcher)
	const text = "nothing to hide here\n"
	if _, err := w.Write([]byte(text)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if out.String() != text {
		t.Errorf("want the text unchanged, got %q", out.String())
	}
}

package redact

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// TestTheFilterCoversEveryEncodedForm is the promise that
// docs/threat-model.md section 3.2 makes. A program often prints a secret
// after it encodes it, and the raw value never appears in that output.
//
// The value holds characters that make the two base64 alphabets differ, so a
// filter that covers only the standard alphabet fails this test.
func TestTheFilterCoversEveryEncodedForm(t *testing.T) {
	const value = "Ab~cd?ef>gh_ij:kl<mn0pqr"
	raw := []byte(value)

	forms := []struct {
		name string
		text string
	}{
		{"the value itself", value},
		{"standard base64", base64.StdEncoding.EncodeToString(raw)},
		{"URL base64, which is what a JWT uses", base64.URLEncoding.EncodeToString(raw)},
		{"lower case hex", hex.EncodeToString(raw)},
		{"upper case hex", strings.ToUpper(hex.EncodeToString(raw))},
		{"a URL query escape", "https://acme.io?q=" + value},
	}

	res := Build(map[string]string{"api_token": value}, Options{})
	for _, f := range forms {
		t.Run(f.name, func(t *testing.T) {
			got := run(res.Matcher, "log line: "+f.text+" end", 7)
			if strings.Contains(got, f.text) {
				t.Errorf("the %s of the value survived the filter:\n%s", f.name, got)
			}
		})
	}
}

// TestAnEncodedFormSurvivesInsideALargerBlock proves the shift handling still
// holds for the URL alphabet. A value inside a larger base64 block does not
// encode to the same characters as the value on its own.
func TestAnEncodedFormSurvivesInsideALargerBlock(t *testing.T) {
	const value = "Ab~cd?ef>gh_ij:kl<mn0pqr"
	res := Build(map[string]string{"api_token": value}, Options{})

	for shift := 0; shift < 3; shift++ {
		body := strings.Repeat("Z", shift) + value + "tail"
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
			text := enc.EncodeToString([]byte(body))
			got := run(res.Matcher, text, 5)
			if got == text {
				t.Errorf("shift %d: nothing was removed from the block:\n%s", shift, got)
			}
		}
	}
}

// TestEncodingsHoldNoValueBelowTheFloor keeps the encoded forms under the same
// rule as the value. Build drops a short value, and it must not put a long
// encoded form of that same short value back.
func TestEncodingsHoldNoValueBelowTheFloor(t *testing.T) {
	res := Build(map[string]string{"pin": "abc"}, Options{})
	if res.Count != 0 {
		t.Fatalf("a value below the floor produced %d needles, want 0", res.Count)
	}
	if len(res.Skipped) != 1 || res.Skipped[0] != "pin" {
		t.Fatalf("the skipped list is %v, want [pin]", res.Skipped)
	}
}

// multiLineKey is a synthetic value in the shape of a PEM private key. It is
// not a key.
const multiLineKey = "-----BEGIN FAKE KEY-----\n" +
	"TXVsdGlMaW5lQm9keU9uZS1RN3hSMm1WbjdwTA\n" +
	"TXVsdGlMaW5lQm9keVR3by1XNGFaOWtKM3NIdA\n" +
	"-----END FAKE KEY-----"

// TestAMultiLineValueIsRemovedInEveryForm covers a value that holds a
// newline. A terminal prints each "\n" as "\r\n", and a program can print the
// body of a key without its first and last line. Both used to pass the filter.
func TestAMultiLineValueIsRemovedInEveryForm(t *testing.T) {
	lines := strings.Split(multiLineKey, "\n")
	forms := []struct {
		name string
		text string
	}{
		{"the value itself", multiLineKey},
		{"the value as a terminal prints it", strings.ReplaceAll(multiLineKey, "\n", "\r\n")},
		{"the first body line alone", lines[1]},
		{"the second body line alone", lines[2]},
	}

	res := Build(map[string]string{"signing_key": multiLineKey}, Options{})
	for _, f := range forms {
		t.Run(f.name, func(t *testing.T) {
			for _, chunk := range []int{1, 7, 4096} {
				got := run(res.Matcher, "log: "+f.text+" end", chunk)
				if strings.Contains(got, f.text) {
					t.Errorf("the %s survived the filter with chunk %d:\n%q", f.name, chunk, got)
				}
				for _, l := range lines[1:3] {
					if strings.Contains(got, l) {
						t.Errorf("a body line survived the filter with chunk %d:\n%q", chunk, got)
					}
				}
			}
		})
	}
}

// TestAnArmourLineIsNotASecret keeps the public boundary line of a PEM value
// in the output. It appears in logs that hold no secret, and a filter that
// removed it would damage them.
func TestAnArmourLineIsNotASecret(t *testing.T) {
	res := Build(map[string]string{"signing_key": multiLineKey}, Options{})
	const text = "expected -----BEGIN FAKE KEY----- at the start"
	if got := run(res.Matcher, text, 4096); got != text {
		t.Errorf("the armour line changed:\n got %q\nwant %q", got, text)
	}
}

// TestAOneLineValueGetsNoLineForms keeps the needle count of an ordinary value
// as it was.
func TestAOneLineValueGetsNoLineForms(t *testing.T) {
	if forms := lineForms("OneLineValue-Z3k9Qw", DefaultMinLen); forms != nil {
		t.Errorf("a value on one line got line forms: %q", forms)
	}
}

// TestOtherEncodersFormsAreRemoved covers the forms that an encoder other than
// Go's writes for the same value. A percent escape can be in lower case, and a
// JSON string can hold "\/" and a raw "<". Go writes neither of these, so a
// filter that uses only Go's encoders misses them.
func TestOtherEncodersFormsAreRemoved(t *testing.T) {
	const value = "k3y/with+plus=eq?q<lt&amp>gt"
	forms := []struct {
		name string
		text string
	}{
		{"a lower case query escape", "k3y%2fwith%2bplus%3deq%3fq%3clt%26amp%3egt"},
		{"a lower case path escape", "k3y%2fwith+plus=eq%3fq%3clt&amp%3egt"},
		{"a JSON string with HTML escapes and an escaped slash", `k3y\/with+plus=eq?q\u003clt\u0026amp\u003egt`},
		{"a JSON string with no HTML escapes", `k3y\/with+plus=eq?q<lt&amp>gt`},
		{"a JSON string with no HTML escapes and a plain slash", `k3y/with+plus=eq?q<lt&amp>gt`},
	}
	res := Build(map[string]string{"api_token": value}, Options{})
	for _, f := range forms {
		t.Run(f.name, func(t *testing.T) {
			got := run(res.Matcher, `{"token":"`+f.text+`"}`, 7)
			if strings.Contains(got, f.text) {
				t.Errorf("the %s of the value survived the filter:\n%s", f.name, got)
			}
		})
	}
}

// TestEachEncoderFormIsRemoved covers a finding of the review of issue 80.
// Each text below is the real output of the named encoder, and not a guess.
// Python, JavaScript and Java escape a different set of characters, and a
// JSON encoder can write a character as \uXXXX.
func TestEachEncoderFormIsRemoved(t *testing.T) {
	cases := []struct {
		value string
		name  string
		text  string
	}{
		{"k3y/with+plus=eq?q<lt&amp>gt", "Python quote", "k3y/with%2Bplus%3Deq%3Fq%3Clt%26amp%3Egt"},
		{"k3y/with+plus=eq?q<lt&amp>gt", "Python quote_plus", "k3y%2Fwith%2Bplus%3Deq%3Fq%3Clt%26amp%3Egt"},
		{"k3y/with+plus=eq?q<lt&amp>gt", "JavaScript encodeURI", "k3y/with+plus=eq?q%3Clt&amp%3Egt"},
		{"k3y/with+plus=eq?q<lt&amp>gt", "Gson", `k3y/with+plus\u003deq?q\u003clt\u0026amp\u003egt`},
		{"tok!en*('x')~y z/9", "JavaScript encodeURIComponent", "tok!en*('x')~y%20z%2F9"},
		{"tok!en*('x')~y z/9", "Python quote with a space", "tok%21en%2A%28%27x%27%29~y%20z/9"},
		{"tok!en*('x')~y z/9", "Python quote_plus with a space", "tok%21en%2A%28%27x%27%29~y+z%2F9"},
		{"tok!en*('x')~y z/9", "Java URLEncoder", "tok%21en*%28%27x%27%29%7Ey+z%2F9"},
		{"tok!en*('x')~y z/9", "Java URLEncoder in lower case", "tok%21en*%28%27x%27%29%7ey+z%2f9"},
		{"s3cr\u00e9t=v\u00e4l\U0001F511 x<y", "Python json.dumps", `s3cr\u00e9t=v\u00e4l\ud83d\udd11 x<y`},
		{"s3cr\u00e9t=v\u00e4l\U0001F511 x<y", "Jackson with ESCAPE_NON_ASCII", `s3cr\u00E9t=v\u00E4l\uD83D\uDD11 x<y`},
		{"s3cr\u00e9t=v\u00e4l\U0001F511 x<y", "JavaScript encodeURIComponent of UTF-8", "s3cr%C3%A9t%3Dv%C3%A4l%F0%9F%94%91%20x%3Cy"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := Build(map[string]string{"api_token": c.value}, Options{})
			for _, chunk := range []int{1, 7, 4096} {
				got := run(res.Matcher, "url="+c.text+"&next=1", chunk)
				if strings.Contains(got, c.text) {
					t.Errorf("the %s form survived the filter with chunk %d:\n%s", c.name, chunk, got)
				}
			}
		})
	}
}

// TestAPlainValueGetsNoExtraForms keeps the needle count of a value with only
// letters and digits as it was. Each encoder writes such a value as it is.
func TestAPlainValueGetsNoExtraForms(t *testing.T) {
	const value = "PlainValue0123456789abcdef"
	got := Encodings(value)
	for _, form := range got {
		if !isBase64OrHex(form) {
			t.Errorf("a plain value got the form %q", form)
		}
	}
	if len(got) > 8 {
		t.Errorf("a plain value got %d forms, want base64 and hex only: %q", len(got), got)
	}
}

// isBase64OrHex reports whether s holds only characters of base64 or hex.
func isBase64OrHex(s string) bool {
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("+/-_", r)) {
			return false
		}
	}
	return true
}

func TestLowerPercent(t *testing.T) {
	cases := map[string]string{
		"":          "",
		"%2F%3D":    "%2f%3d",
		"abc%2Fdef": "abc%2fdef",
		"ABC%":      "ABC%",
		"%A":        "%A",
		"x%AFy%0Bz": "x%afy%0bz",
	}
	for in, want := range cases {
		if got := lowerPercent(in); got != want {
			t.Errorf("lowerPercent(%q) = %q, want %q", in, got, want)
		}
	}
}

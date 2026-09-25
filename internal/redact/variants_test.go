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
		{"a JSON string with an escaped slash", `k3y\/with+plus=eq?q<lt&amp>gt`},
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

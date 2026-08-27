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

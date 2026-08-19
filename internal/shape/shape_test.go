// The test of the shape package.
//
// The randomness rule decides every value whose name says nothing, so it is
// the last thing between a credential and the agent that reads the file. The
// package had no test at all before this one.
//
// No value here is a real credential. The random values are generated from a
// fixed seed, so a failure can be repeated.
package shape_test

import (
	"math"
	"math/rand"
	"strings"
	"testing"

	"github.com/ByteFinch-Technologies/secretveil/internal/shape"
)

// alphabets are the character sets that a credential is drawn from.
var alphabets = map[string]string{
	"hex":       "0123456789abcdef",
	"hex-upper": "0123456789ABCDEF",
	"alnum":     "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"base64":    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/",
	"base64url": "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_",
	"letters":   "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
}

// token draws one value of n characters from an alphabet.
func token(r *rand.Rand, set string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = set[r.Intn(len(set))]
	}
	return string(b)
}

// maxOpen is the share of real random tokens that the rule is allowed to miss.
//
// The rule is the last one to run, so a miss here is a credential in plain
// text. The number is a ratchet: lower it when the rule improves, never raise
// it to make a failing test pass.
const maxOpen = 0.03

// TestARandomTokenIsVeiled measures the rule against real random tokens, at
// every alphabet and every length that a credential is issued in.
//
// The flat cutoff that this rule replaced measured 74.9 per cent open for
// hexadecimal at 24 characters, because the cutoff of 3.6 bits sat at the
// middle of the distribution of real random tokens of that length.
func TestARandomTokenIsVeiled(t *testing.T) {
	const runs = 2000
	r := rand.New(rand.NewSource(20260819))
	for _, name := range []string{"hex", "hex-upper", "alnum", "base64", "base64url", "letters"} {
		for _, n := range []int{20, 24, 32, 40, 48, 64} {
			open := 0
			for i := 0; i < runs; i++ {
				if !shape.LooksRandom(token(r, alphabets[name], n)) {
					open++
				}
			}
			if share := float64(open) / runs; share > maxOpen {
				t.Errorf("%s at %d characters: %d of %d stay open (%.1f%%), and the limit is %.1f%%",
					name, n, open, runs, share*100, maxOpen*100)
			}
		}
	}
}

// TestAConfigValueStaysOpen holds the values that must never be veiled.
//
// A false veil breaks nothing, because the real value still reaches the child
// process. It does hide information that the agent needs, and a tool that
// hides a log level and a time zone is a tool that people switch off. So this
// list is as much a part of the rule as the list above.
func TestAConfigValueStaysOpen(t *testing.T) {
	values := []string{
		// A path. Every part is a lower case word.
		"/usr/local/share/ca-certificates/extra/company.crt",
		"/home/runner/work/repository/repository/dist",
		"node_modules/.bin/typescript-language-server",
		"src/components/dashboard/SettingsPanel.tsx",
		"America/Argentina/ComodRivadavia",
		// A name that a person wrote, in each of the four styles.
		"ThisIsAVeryLongCompanyNameHereIndeed",
		"a-very-long-kebab-case-feature-flag-name",
		"snake_case_configuration_option_value",
		"postgresql-14-main-cluster-primary",
		"MyCompanyProductionKubernetesCluster",
		"CHANGEME_REPLACE_THIS_BEFORE_DEPLOY",
		"my-bucket-name-for-static-assets",
		"GoogleAnalyticsMeasurementProtocol",
		"WebkitAppearanceNoneImportantValue",
		"com.example.myapplication.production",
		"your-project-id.appspot.com",
		// A list, an address and a time. None of them is a token.
		"UTF-8,ISO-8859-1,windows-1252",
		"application/vnd.api+json;charset=utf-8",
		"registry.example.com:5000/team/service:1.4.2",
		"2026-08-19T10:30:00.123456789Z",
		"arn:aws:iam::123456789012:role/service-role",
		"eu-central-1a,eu-central-1b,eu-central-1c",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
		"debug,info,warn,error,fatal",
		// A value that repeats. It reaches the length of a token and holds
		// almost no information, and the distinct-character floor catches it.
		"deadbeefdeadbeefdeadbeefdeadbeef",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"abcdefabcdefabcdefabcdefabcdefab",
		// Digits alone. An identifier, an account number and a timestamp are
		// all digits, and this is a stated limit of the tool.
		"0123456789012345678901234567890123456789",
	}
	for _, v := range values {
		if shape.LooksRandom(v) {
			t.Errorf("%q is veiled and it is not a secret", v)
		}
	}
}

// TestAShortValueStaysOpen pins the floor. A value that cannot hold 80 bits is
// not veiled whatever its entropy, because a secret that short is guessable
// and veiling it only hides a setting.
func TestAShortValueStaysOpen(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	for _, n := range []int{4, 8, 12, 16, 19} {
		for i := 0; i < 200; i++ {
			v := token(r, alphabets["hex"], n)
			if shape.LooksRandom(v) {
				t.Fatalf("%q is %d characters and it is veiled", v, n)
			}
		}
	}
}

// TestTheAlphabetIsCounted checks the alphabet size, which sets the threshold.
//
// A hexadecimal token of one case is drawn from 16 symbols. Counting its
// digits and its letters as 36 would raise the threshold above the ceiling of
// the alphabet, and then no hexadecimal value could ever be veiled.
func TestTheAlphabetIsCounted(t *testing.T) {
	cases := []struct {
		value string
		want  int
		ok    bool
	}{
		{"0123456789abcdef", 16, true},
		{"0123456789ABCDEF", 16, true},
		// Two cases of hexadecimal is not hexadecimal. It is still a token,
		// over the 52 letters, because it holds no digit.
		{"deadBEEF", 52, true},
		{"deadBEEF01", 62, true},
		{"abcdefghij", 26, true},
		{"abcdefghij0123", 36, true},
		{"abcXYZ012", 62, true},
		{"abcXYZ012+/", 67, true},
		{"0123456789", 0, false}, // Digits alone are refused.
		{"has space", 0, false},
		{"has:colon", 0, false},
	}
	for _, c := range cases {
		got, ok := shape.TokenAlphabetForTest(c.value)
		if ok != c.ok {
			t.Errorf("%q: read as a token is %v and %v was wanted", c.value, ok, c.ok)
			continue
		}
		if ok && got != c.want {
			t.Errorf("%q: alphabet is %d and %d was wanted", c.value, got, c.want)
		}
	}
}

// TestALabelledTokenKeepsItsLabel checks the span, not only the verdict.
//
// The label of a Telegram credential names the bot and is public. Veiling the
// whole value would hide which bot the row is about for no gain.
func TestALabelledTokenKeepsItsLabel(t *testing.T) {
	const value = "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw"
	start, end, ok := shape.LabelledToken(value)
	if !ok {
		t.Fatalf("%q is not read as a labelled token", value)
	}
	if value[:start] != "123456789:" {
		t.Errorf("the label kept is %q and \"123456789:\" was wanted", value[:start])
	}
	if end != len(value) {
		t.Errorf("the span ends at %d and %d was wanted", end, len(value))
	}

	// A colon divides many things that are not a label and a token.
	for _, v := range []string{
		"redis:6379",
		"03:30:00",
		"2001:db8::8a2e:370:7334",
		"primary:replica",
		"com.example:my-artifact:1.2.3",
		"https://example.com/a:b",
		"nocolonhere",
		"trailing:",
	} {
		if _, _, ok := shape.LabelledToken(v); ok {
			t.Errorf("%q is read as a labelled token and it is not one", v)
		}
	}
}

// TestEntropyIsMeasured pins the estimator that the threshold is compared to.
func TestEntropyIsMeasured(t *testing.T) {
	cases := []struct {
		value string
		want  float64
	}{
		{"", 0},
		{"aaaa", 0},
		{"ab", 1},
		{"abcd", 2},
		{"aabb", 1},
	}
	for _, c := range cases {
		if got := shape.Entropy(c.value); math.Abs(got-c.want) > 1e-9 {
			t.Errorf("Entropy(%q) is %v and %v was wanted", c.value, got, c.want)
		}
	}
}

// TestTheCommentTellsNoValue is the promise that the rewritten file keeps.
//
// The comment sits beside a handle in a file that an agent reads. It may say
// how long the value is and what it is made of. It may never say what it is.
func TestTheCommentTellsNoValue(t *testing.T) {
	r := rand.New(rand.NewSource(11))
	for i := 0; i < 500; i++ {
		v := token(r, alphabets["alnum"], 8+r.Intn(56))
		c := shape.Of(v).Comment()
		for n := 3; n <= len(v); n++ {
			for j := 0; j+n <= len(v); j++ {
				if strings.Contains(c, v[j:j+n]) {
					t.Fatalf("the comment %q holds %q from the value %q", c, v[j:j+n], v)
				}
			}
		}
	}
}

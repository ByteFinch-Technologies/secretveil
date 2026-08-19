// Package shape describes a secret value without revealing it.
//
// The agent needs three facts about a secret: that it exists, what it is for,
// and whether it has the right form. This package supplies the third fact. It
// never returns any part of the value, except a short prefix that a public
// identifier already exposes, for example the "AKIA" of an AWS key id.
package shape

import (
	"fmt"
	"math"
	"regexp"
	"strings"
)

// Shape is the public description of a value.
type Shape struct {
	Length  int     `json:"length"`
	Charset string  `json:"charset"`
	Entropy float64 `json:"entropy"`
	// Prefix holds a leading substring that is safe to show, or "".
	Prefix string `json:"prefix,omitempty"`
}

// Of measures a value.
func Of(value string) Shape {
	return Shape{
		Length:  len(value),
		Charset: charsetOf(value),
		Entropy: Entropy(value),
	}
}

// WithPrefix returns a copy that keeps the first n bytes as a visible prefix.
func (s Shape) WithPrefix(value string, n int) Shape {
	if n > len(value) {
		n = len(value)
	}
	s.Prefix = value[:n]
	return s
}

// Comment renders the one-line description that goes into the .env file.
func (s Shape) Comment() string {
	return fmt.Sprintf("sv: %d chars, %s, entropy %.1f", s.Length, s.Charset, s.Entropy)
}

// Entropy returns the Shannon entropy of a value, in bits per byte.
func Entropy(value string) float64 {
	if value == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(value); i++ {
		counts[value[i]]++
	}
	total := float64(len(value))
	sum := 0.0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / total
		sum -= p * math.Log2(p)
	}
	return sum
}

const (
	hexChars    = "0123456789abcdefABCDEF"
	base64Extra = "+/=-_"
)

func charsetOf(value string) string {
	if value == "" {
		return "empty"
	}
	allHex, allAlnum, allBase64, allASCII := true, true, true, true
	for i := 0; i < len(value); i++ {
		c := value[i]
		if !strings.ContainsRune(hexChars, rune(c)) {
			allHex = false
		}
		alnum := c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		if !alnum {
			allAlnum = false
			if !strings.ContainsRune(base64Extra, rune(c)) {
				allBase64 = false
			}
		}
		if c < 0x20 || c > 0x7e {
			allASCII = false
		}
	}
	switch {
	case allHex:
		return "hex"
	case allAlnum:
		return "alnum"
	case allBase64:
		return "base64"
	case allASCII:
		return "ascii"
	default:
		return "mixed"
	}
}

// ------------------------------------------------------------- randomness

// The randomness rule.
//
// The old rule was a flat cutoff: Entropy(value) > 3.6. That number is wrong
// for two reasons, and together they opened three quarters of the short
// credentials measured.
//
// Hexadecimal has a ceiling of 4 bits per character, and the plug-in entropy
// estimator is biased downward on a short sample: a 24-character hex token
// drawn at random measures a median of 3.63 bits, not 4. So the 3.6 cutoff sat
// at the middle of the distribution of real random tokens and behaved as a
// coin flip. It was also too strict for a base64 token, whose ceiling is 6.
//
// The bound below is length aware and alphabet aware. For a sample of n
// characters drawn uniformly from an alphabet of k symbols, the quantity
//
//	2 n ln2 (log2 k - H)
//
// follows a chi-squared distribution with k-1 degrees of freedom. So the
// entropy of a real random token falls below log2(k) by an amount that shrinks
// as the sample grows, and the threshold has to shrink with it.

// z999 is the 0.999 quantile of the standard normal distribution.
const z999 = 3.090232

// chi999 approximates the 0.999 quantile of the chi-squared distribution with
// df degrees of freedom, by the Wilson and Hilferty transformation.
//
// A table was written out by hand first. The approximation reproduces it to
// better than half a percent, and it answers for every alphabet size instead
// of the four that were tabulated:
//
//	df      15      31      61      63
//	table   37.70   61.10   100.95  103.52
//	this    37.84   61.20   100.96  103.51
//
// Where it errs it errs high, which lowers the threshold and veils more.
func chi999(df int) float64 {
	d := float64(df)
	t := 1 - 2/(9*d) + z999*math.Sqrt(2/(9*d))
	return d * t * t * t
}

// minEntropy returns the lowest entropy that a real random token of n
// characters over an alphabet of k symbols is expected to reach.
func minEntropy(n, k int) float64 {
	if n <= 0 || k <= 1 {
		return math.Inf(1)
	}
	return math.Log2(float64(k)) - chi999(k-1)/(2*float64(n)*math.Ln2)
}

// tokenAlphabet returns the number of symbols a value could have been drawn
// from, and whether the value reads as a token at all.
//
// It is deliberately separate from charsetOf. charsetOf writes its answer into
// the rewritten file as a comment that a person reads, so its words must stay
// as they are. This function feeds a threshold and has to be exact: a hex
// token of one case is drawn from 16 symbols and not from the 36 that a naive
// count of digits plus letters would give.
func tokenAlphabet(value string) (int, bool) {
	var digit, lower, upper, extra bool
	lowerHex, upperHex := true, true
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c >= '0' && c <= '9':
			digit = true
		case c >= 'a' && c <= 'z':
			lower = true
			upperHex = false
			if c > 'f' {
				lowerHex = false
			}
		case c >= 'A' && c <= 'Z':
			upper = true
			lowerHex = false
			if c > 'F' {
				upperHex = false
			}
		case strings.IndexByte(base64Extra, c) >= 0:
			extra = true
			lowerHex, upperHex = false, false
		default:
			return 0, false
		}
	}
	// A value of digits alone is refused. An account number, an identifier and
	// a timestamp are all digits, and none of them is a secret. This is a
	// stated limit of the tool and not an oversight.
	if !lower && !upper && !extra {
		return 0, false
	}
	if lowerHex || upperHex {
		return 16, true
	}
	k := 0
	if digit {
		k += 10
	}
	if lower {
		k += 26
	}
	if upper {
		k += 26
	}
	if extra {
		k += len(base64Extra)
	}
	return k, true
}

// distinct counts how many different characters a value holds.
func distinct(value string) int {
	var seen [256]bool
	n := 0
	for i := 0; i < len(value); i++ {
		if !seen[value[i]] {
			seen[value[i]] = true
			n++
		}
	}
	return n
}

// minDistinct is the fewest different characters that a real random token of n
// symbols over an alphabet of k is allowed to hold.
//
// The expected count is k(1-(1-1/k)^n). Half of that is a loose floor, and it
// is here to catch a value that repeats: deadbeefdeadbeefdeadbeef holds five
// different characters where a random hex token of that length holds about
// thirteen.
func minDistinct(n, k int) int {
	if n <= 0 || k <= 1 {
		return 0
	}
	expected := float64(k) * (1 - math.Pow(1-1/float64(k), float64(n)))
	return int(expected / 2)
}

// LooksRandom is the last-resort test for a secret with an unusual name.
//
// High entropy alone is not enough. A URL, a path and a sentence all reach an
// entropy above 3.6, and veiling them hides information the agent needs and
// protects nothing. So the value must also look like a token: no whitespace,
// no scheme, a token alphabet, and enough of it to carry a secret.
func LooksRandom(value string) bool {
	n := len(value)
	if n < 20 {
		return false
	}
	if strings.ContainsAny(value, " \t\n\r") {
		return false
	}
	// A scheme means a URL, and a URL is an address the agent needs to read.
	// The old rule refused any value holding two slashes, which threw away
	// every base64 token that happened to hold one, and base64 holds a slash
	// naturally about once in every sixty characters.
	if strings.Contains(value, "://") {
		return false
	}
	if looksLikePath(value) || looksLikeIdentifier(value) {
		return false
	}
	k, ok := tokenAlphabet(value)
	if !ok {
		return false
	}
	// A short token over a small alphabet cannot hold a secret whatever its
	// entropy. Eighty bits is the floor, which is 20 hexadecimal characters.
	if float64(n)*math.Log2(float64(k)) < 80 {
		return false
	}
	if distinct(value) < minDistinct(n, k) {
		return false
	}
	return Entropy(value) >= minEntropy(n, k)
}

// looksLikePath reports whether a value reads as a file path.
//
// A path divides on the slash into parts, and enough of those parts are plain
// lower case words. The lower case is the whole test. A first version asked
// only that a part hold three lower case letters in a row, and a base64 token
// holds a slash about once in every sixty-four characters, so a long token
// broke into two long parts and each one held such a run by chance. The
// measured miss rate for base64 at sixty-four characters was 14 per cent.
//
// A part of a real path is written in lower case: site-packages, db_password,
// ca-certificates, python3.11. A part of a random token of that length holds
// an upper case letter with a probability above 0.9999. A path written with
// capitals is not lost, because looksLikeIdentifier reads it as a name.
func looksLikePath(value string) bool {
	parts := strings.Split(value, "/")
	if len(parts) < 3 {
		return false
	}
	words := 0
	for _, p := range parts {
		if p == "" {
			continue
		}
		if len(p) > 64 {
			return false
		}
		if pathWord.MatchString(p) && letterCount(p) >= 3 {
			words++
		}
	}
	return words >= 2
}

// pathWord matches a part of a path: lower case letters, digits and the three
// characters that a file name uses to divide a word. An upper case letter is
// refused, and that refusal is what keeps a token out.
var pathWord = regexp.MustCompile(`^[a-z0-9._-]+$`)

// letterCount counts the letters of a value.
func letterCount(value string) int {
	n := 0
	for i := 0; i < len(value); i++ {
		if c := value[i]; c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			n++
		}
	}
	return n
}

// looksLikeIdentifier reports whether a value is built out of words.
//
// A long name written by a person reaches the same entropy as a token of the
// same length, so the bound alone cannot tell them apart. These all measure
// above the threshold and none of them is a secret:
//
//	MyCompanyProductionKubernetesCluster
//	snake_case_configuration_option_value
//	my-bucket-name-for-static-assets
//	CHANGEME_REPLACE_THIS_BEFORE_DEPLOY
//
// What separates them from a token is structure. The value divides into parts,
// every part is letters alone or digits alone, and nearly every part is long
// enough to be a word. A random token divides into parts that mix letters and
// digits, because nothing put a boundary where the case changes.
//
// The two counts are both needed and a first version had neither. Asking only
// for three words let a random token of letters alone through every time: a
// mixed-case string of 64 characters breaks at about thirty case changes, and
// three of those parts reach three letters by chance alone. The measured miss
// rate for that alphabet was 100 per cent.
//
// So the parts are judged as a whole. A name that a person wrote is almost all
// words, and it holds at most one part of one character. A random token is the
// opposite: half of its parts are one character long, because a case change
// falls between any two characters with even chance.
//
// The known cost is a passphrase of separated words under a name that says
// nothing, for example SETTING=correct-horse-battery-staple. That is the
// stated limit of a value made of words, and a name that says anything at all
// catches it one rule earlier.
func looksLikeIdentifier(value string) bool {
	if len(value) > 128 {
		return false
	}
	parts := identifierParts(value)
	if len(parts) < 3 {
		return false
	}
	words, singles := 0, 0
	for _, p := range parts {
		letters, digits := 0, 0
		for i := 0; i < len(p); i++ {
			switch c := p[i]; {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
				letters++
			case c >= '0' && c <= '9':
				digits++
			default:
				return false
			}
		}
		// A part that mixes a letter and a digit is not a word.
		if letters > 0 && digits > 0 {
			return false
		}
		if len(p) == 1 {
			singles++
		}
		if letters >= 3 {
			words++
		}
	}
	// One part of one character is the initial in MyCompanyName. Two is a
	// value that broke where no person put a boundary.
	if singles > 1 {
		return false
	}
	// Three quarters of the parts must be words, and the parts must be long
	// on average. A random token of letters alone breaks into parts of about
	// two characters, because a case change falls between any two characters
	// with even chance. A name that a person wrote breaks into whole words.
	if words*4 < len(parts)*3 {
		return false
	}
	letters := 0
	for _, p := range parts {
		letters += len(p)
	}
	return words >= 3 && letters*2 >= len(parts)*7
}

// identifierParts splits a value the way a person writes a name: on a
// separator, and where the case changes.
func identifierParts(value string) []string {
	var parts []string
	start := 0
	flush := func(end int) {
		if end > start {
			parts = append(parts, value[start:end])
		}
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == '_' || c == '-' || c == '.' || c == '/' || c == '+' || c == '=' {
			flush(i)
			start = i + 1
			continue
		}
		if i == 0 {
			continue
		}
		p := value[i-1]
		lowerToUpper := isLowerOrDigit(p) && c >= 'A' && c <= 'Z'
		endOfRun := p >= 'A' && p <= 'Z' && c >= 'a' && c <= 'z' && i >= 2 &&
			value[i-2] >= 'A' && value[i-2] <= 'Z'
		if lowerToUpper {
			flush(i)
			start = i
		} else if endOfRun {
			flush(i - 1)
			start = i - 1
		}
	}
	flush(len(value))
	return parts
}

func isLowerOrDigit(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}

// TokenAlphabetForTest exposes the alphabet size to the test of this package.
func TokenAlphabetForTest(value string) (int, bool) { return tokenAlphabet(value) }

// LabelledToken finds a random token that a plain label introduces.
//
// A Telegram bot credential is written as 123456789:AAHdqTcvCH1vGWJ..., where
// the number is the identifier of the bot and is public, and the part after
// the colon is the secret. The whole value holds a colon, so no token rule
// reads it, and the whole value was left in the clear.
//
// The result is a span and not a verdict, so the rewritten file keeps the
// identifier and hides only the token: 123456789:sv://telegram_bot. A person
// who reads the file still knows which bot it is.
//
// The label must be plain. A colon divides a host from a port and an hour from
// a minute, and neither half of those is a token, so the test that the second
// half is random is what keeps them open.
func LabelledToken(value string) (start, end int, ok bool) {
	i := strings.LastIndexAny(value, ":|")
	if i <= 0 || i == len(value)-1 {
		return 0, 0, false
	}
	label := value[:i]
	if len(label) > 32 || !plainLabel.MatchString(label) {
		return 0, 0, false
	}
	if !LooksRandom(value[i+1:]) {
		return 0, 0, false
	}
	return i + 1, len(value), true
}

// plainLabel matches a label that names something. A slash, a space or an at
// sign means the value is a URL or an address and not a labelled token.
var plainLabel = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

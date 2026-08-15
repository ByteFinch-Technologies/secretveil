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

// LooksRandom is the last-resort test for a secret with an unusual name.
//
// High entropy alone is not enough. A URL, a path and a sentence all reach an
// entropy above 3.6, and veiling them hides information the agent needs and
// protects nothing. So the value must also look like a token: no whitespace,
// no path or scheme structure, and a token charset.
func LooksRandom(value string) bool {
	if len(value) <= 20 {
		return false
	}
	if strings.ContainsAny(value, " \t\n\r") {
		return false
	}
	if strings.Contains(value, "://") || strings.HasPrefix(value, "/") || strings.Contains(value, "//") {
		return false
	}
	switch charsetOf(value) {
	case "hex", "alnum", "base64":
	default:
		return false
	}
	return Entropy(value) > 3.6
}

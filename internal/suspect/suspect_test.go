package suspect_test

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/ByteFinch-Technologies/secretveil/internal/suspect"
)

// Every token in this file is generated. No credential-shaped literal may be
// written into any file of this repository, and test/hygiene enforces that on
// every build. See the note in internal/shape/shape_test.go for the three
// times the rule was broken before the check existed.
const alnum = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func token(r *rand.Rand, set string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = set[r.Intn(len(set))]
	}
	return string(b)
}

// TestAVendorOpeningIsReported covers the value that the shape rules missed.
//
// A value that starts the way a vendor credential starts and that still
// reached this package is either a key of a length the tool does not know, or
// a placeholder somebody left behind. Both need a person to look.
func TestAVendorOpeningIsReported(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	for _, start := range []string{"sk-", "sk_live_", "npm_", "ghp_", "AKIA", "AIza", "xox", "glpat-"} {
		for _, n := range []int{4, 9, 22, 61} {
			v := start + token(r, alnum, n)
			if suspect.Reason(v) == "" {
				t.Errorf("a value that starts %q and is %d characters long was not reported", start, len(v))
			}
		}
	}
}

// TestASettingIsNotReported is the cost side. Every value here is one that a
// real project holds and that no person should ever be asked about.
func TestASettingIsNotReported(t *testing.T) {
	for _, v := range []string{
		"production", "development", "info", "debug", "true", "false", "3000",
		"8080", "postgres", "redis", "eu-central-1", "us-east-1", "1.24.3",
		"v2.10.0", "application/json", "text/html; charset=utf-8",
		"/var/run/secrets/token", "/usr/local/share/app/config",
		"localhost", "db.internal.example.com", "Europe/Berlin",
		"my-service-name", "acme-web-frontend", "HS256", "RS256",
		"X-Request-Id", "X-Custom-Auth-Header", "Bearer",
		"a very long human sentence that a person wrote by hand",
		"node_modules/.bin/next", "public/assets/images/logo.svg",
		"https://api.example.com/v1/orders", "0", "1", "",
	} {
		if reason := suspect.Reason(v); reason != "" {
			t.Errorf("a setting was reported: %q gave %q", v, reason)
		}
	}
}

// TestAShortValueIsNotReported holds the floor. A value of a few characters
// carries too little to guess about, and guessing at that length would report
// most of a .env file.
func TestAShortValueIsNotReported(t *testing.T) {
	r := rand.New(rand.NewSource(4))
	for n := 1; n < 12; n++ {
		for i := 0; i < 200; i++ {
			v := token(r, alnum, n)
			if reason := suspect.Reason(v); reason != "" {
				t.Fatalf("a value of %d characters was reported: %q", n, reason)
			}
		}
	}
}

// TestTheReasonTellsNoValue is the rule that matters most in this package.
//
// The reason reaches a terminal, a log file and a build server record. A
// reason that quoted the value it warned about would put that value in one
// more place, which is the fault the whole tool exists to stop.
func TestTheReasonTellsNoValue(t *testing.T) {
	r := rand.New(rand.NewSource(5))
	for i := 0; i < 500; i++ {
		v := token(r, alnum, 12+r.Intn(50))
		reason := suspect.Reason(v)
		if reason == "" {
			continue
		}
		for n := 3; n+n <= len(v); n++ {
			if strings.Contains(reason, v[:n]) || strings.Contains(reason, v[len(v)-n:]) {
				t.Fatalf("the reason repeats part of the value it warns about: %q", reason)
			}
		}
	}
}

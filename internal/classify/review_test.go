package classify_test

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/ByteFinch-Technologies/secretveil/internal/classify"
	"github.com/ByteFinch-Technologies/secretveil/internal/corpus"
)

// maxReported is the share of open corpus rows that may be reported.
//
// The report is the only defence for a value that no rule knows, so it has to
// fire. It also has to stay quiet enough to be read. A report that names one
// row in twenty is a report that a developer skims once and then ignores, and
// an ignored report defends nothing.
const maxReported = 0.03

func TestFewOpenRowsAreReported(t *testing.T) {
	rows, reported := 0, 0
	var named []string
	for _, r := range corpus.Generate() {
		if r.Want != corpus.Open {
			continue
		}
		rows++
		if d := classify.Classify(r.Key, r.Value); d.Review {
			reported++
			named = append(named, r.Key)
		}
	}
	share := float64(reported) / float64(rows)
	t.Logf("%d of %d open rows are reported (%.2f%%): %s",
		reported, rows, 100*share, strings.Join(named, ", "))
	if share > maxReported {
		t.Errorf("the report names %.2f%% of the open rows and the bound is %.2f%%",
			100*share, 100*maxReported)
	}
}

// tokenSets are the alphabets a vendor draws a key from.
var tokenSets = map[string]string{
	"hex":        "0123456789abcdef",
	"loweralnum": "0123456789abcdefghijklmnopqrstuvwxyz",
	"alnum":      "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"base64":     "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/",
}

// minSeen is the share of short tokens that must be either veiled or reported.
const minSeen = 0.95

// TestAShortTokenIsSeen covers the gap that the randomness rule cannot close.
//
// The randomness rule needs twenty characters and eighty bits before it will
// veil, because below that a real setting and a real token look the same and
// veiling would take the log level away. A key of sixteen characters is
// therefore invisible to it. This test says that such a key still reaches a
// person, under a name that says nothing at all.
func TestAShortTokenIsSeen(t *testing.T) {
	r := rand.New(rand.NewSource(11))
	const runs = 500
	for _, name := range []string{"hex", "loweralnum", "alnum", "base64"} {
		set := tokenSets[name]
		for _, n := range []int{16, 18, 19} {
			seen := 0
			for i := 0; i < runs; i++ {
				b := make([]byte, n)
				for j := range b {
					b[j] = set[r.Intn(len(set))]
				}
				d := classify.Classify("SETTING", string(b))
				if d.Class != classify.Open || d.Review {
					seen++
				}
			}
			share := float64(seen) / runs
			t.Logf("%-11s n=%d seen %.1f%%", name, n, 100*share)
			if share < minSeen {
				t.Errorf("%s at %d characters reaches a person %.1f%% of the time, and the floor is %.0f%%",
					name, n, 100*share, 100*minSeen)
			}
		}
	}
}

// TestReviewNeverChangesTheClass is the promise that makes the report cheap to
// be wrong about. The mark is advice to a person. It never hides a value and
// it never shows one.
func TestReviewNeverChangesTheClass(t *testing.T) {
	r := rand.New(rand.NewSource(12))
	set := tokenSets["base64"]
	for i := 0; i < 2000; i++ {
		b := make([]byte, 1+r.Intn(60))
		for j := range b {
			b[j] = set[r.Intn(len(set))]
		}
		d := classify.Classify("SETTING", string(b))
		if d.Review && d.Class != classify.Open {
			t.Fatalf("a %s value carries a review mark, and only an open value may", d.Class)
		}
	}
}

// TestTheReviewReasonTellsNoValue repeats the check that internal/suspect
// makes, one layer up, because this is the layer that the report reads from.
func TestTheReviewReasonTellsNoValue(t *testing.T) {
	r := rand.New(rand.NewSource(13))
	set := tokenSets["alnum"]
	for i := 0; i < 1000; i++ {
		b := make([]byte, 12+r.Intn(50))
		for j := range b {
			b[j] = set[r.Intn(len(set))]
		}
		v := string(b)
		d := classify.Classify("SETTING", v)
		if d.Reason == "" {
			continue
		}
		for n := 3; n+n <= len(v); n++ {
			if strings.Contains(d.Reason, v[:n]) || strings.Contains(d.Reason, v[len(v)-n:]) {
				t.Fatalf("the reason repeats part of the value it warns about: %q", d.Reason)
			}
		}
	}
}

// Package fixture gives each test its own synthetic secret value.
//
// One shared value used to stand in for a secret across the whole suite. A
// test that hides value A and then looks for value A passes also when the
// code hides every string of that shape, so a shared value cannot show that
// a filter matched the value the store holds and not some other one. A value
// for each test and each role can.
//
// Every value is made from a hash of the test name and the role. It is
// synthetic, it is not a credential, and it has the shape of no vendor, so
// the hygiene test in test/hygiene does not read it as one. It is also never
// written as a literal, so no two packages can share one by accident.
package fixture

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/ByteFinch-Technologies/secretveil/internal/shape"
)

// prefix starts every value. No vendor issues a key that starts with it, so a
// value can never match a vendor shape by chance.
const prefix = "fx"

// alphabet is letters and digits only. A value with no punctuation is a value
// that every file format in the suite can hold with no quotes.
const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// Value returns the value of one role in one test, 24 characters long.
//
// The role names what the value does in the test: the value the store holds,
// the value that must not match, the value a second file holds. Two roles in
// one test give two different values.
//
// A subtest gets the value of its top-level test. A test often makes the
// project in the parent and checks the output in a subtest, and the check
// must look for the value that the project holds.
func Value(t testing.TB, role string) string {
	t.Helper()
	return derive(t, role, 24)
}

// Long returns a value of 48 characters, for a test of a rule that reads the
// length of a run.
func Long(t testing.TB, role string) string {
	t.Helper()
	return derive(t, role, 48)
}

func derive(t testing.TB, role string, n int) string {
	t.Helper()
	name := t.Name()
	if i := strings.IndexByte(name, '/'); i >= 0 {
		name = name[:i]
	}

	var b strings.Builder
	b.WriteString(prefix)
	for block := byte(0); b.Len() < n; block++ {
		sum := sha256.Sum256([]byte(name + "\x00" + role + "\x00" + string(rune('0'+block))))
		for _, c := range sum {
			if b.Len() == n {
				break
			}
			b.WriteByte(alphabet[int(c)%len(alphabet)])
		}
	}
	v := b.String()

	// A value that does not look random is not read as a secret, and a test
	// that uses it would pass for the wrong reason. A hash almost never gives
	// one, and the check makes the rare case loud.
	if !shape.LooksRandom(v) {
		t.Fatalf("the fixture for %s role %q does not look random: %s", name, role, v)
	}
	return v
}

// The two cases in this file guard the report, and not the migration.
//
// They are here rather than in internal/cli because both of them exist to be
// independent of the classifier. A test that asked internal/classify what it
// thought would repeat the fault it is written to catch.
package adversarial

import (
	"math/rand"
	"path/filepath"
	"strings"
	"testing"
)

// blandValue makes a value that no rule recognises: fourteen characters is
// under the floor of the randomness rule, and the alphabet is the one a vendor
// uses.
func blandValue(seed int64, n int) string {
	const set = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	r := rand.New(rand.NewSource(seed))
	b := make([]byte, n)
	for i := range b {
		b[i] = set[r.Intn(len(set))]
	}
	return string(b)
}

// TestDoctorFindsAPlaintextThatTheClassifierCallsOpen is the reason the
// plaintext check was rewritten.
//
// doctor used to prove that no plaintext was left by asking the classifier
// what each value was, and then reading "open" as "this is not a secret". That
// is a circle. The one fault the check exists to find is a value the
// classifier does not recognise, and for that value the check reported a clean
// project every time.
//
// Here the same value sits in two files. In the first its name says it is a
// secret, so it reaches the store. In the second its name says nothing, so the
// classifier calls it open and leaves it in the file in full. doctor must
// still find the second one, and it must fail.
func TestDoctorFindsAPlaintextThatTheClassifierCallsOpen(t *testing.T) {
	root := t.TempDir()
	value := blandValue(101, 14)
	write(t, filepath.Join(root, "package.json"), "{}\n")
	write(t, filepath.Join(root, ".env"), "PORT=3000\nACME_TOKEN="+value+"\n")
	write(t, filepath.Join(root, ".env.local"), "SOMETHING="+value+"\n")

	if res := sv(t, root, nil, "init", "-y"); res.code != 0 {
		t.Fatalf("init failed with code %d:\n%s", res.code, res.all())
	}
	// The premise of the case. If init had veiled the second one, the case
	// would pass without testing anything.
	if body := read(t, filepath.Join(root, ".env.local")); !strings.Contains(body, value) {
		t.Fatalf("this case needs the value to stay in .env.local, and it did not:\n%s", body)
	}

	res := sv(t, root, nil, "doctor")
	if res.code != 1 {
		t.Errorf("doctor exited %d and it must exit 1 when a plaintext secret is left:\n%s",
			res.code, res.all())
	}
	if !strings.Contains(res.all(), ".env.local") {
		t.Errorf("doctor did not name .env.local:\n%s", res.all())
	}
	if strings.Contains(res.all(), value) {
		t.Errorf("doctor printed the value it warned about:\n%s", res.all())
	}
}

// TestInitNamesAValueThatNoRuleRecognised covers the path that prints the most
// dangerous sentence in the tool.
//
// A project whose every value reads as open never reaches the table. It used
// to get one line, "There is no secret to move", and nothing else. That line
// claims the rules looked and found nothing, when what they did was recognise
// nothing.
func TestInitNamesAValueThatNoRuleRecognised(t *testing.T) {
	root := t.TempDir()
	value := blandValue(202, 14)
	write(t, filepath.Join(root, "package.json"), "{}\n")
	write(t, filepath.Join(root, ".env"), "PORT=3000\nLOG_LEVEL=debug\nACME_BLURB="+value+"\n")

	res := sv(t, root, nil, "init", "-y")
	if res.code != 0 {
		t.Fatalf("init exited %d:\n%s", res.code, res.all())
	}
	out := res.all()
	if strings.Contains(out, "There is no secret to move") {
		t.Errorf("init claimed there is no secret while a value waits for a person:\n%s", out)
	}
	if !strings.Contains(out, "ACME_BLURB") {
		t.Errorf("init did not name the value that no rule recognised:\n%s", out)
	}
	if strings.Contains(out, value) {
		t.Errorf("init printed the value it warned about:\n%s", out)
	}
	// The advice has to be one the developer can carry out with the version
	// they are holding.
	if !strings.Contains(out, "rename the variable") {
		t.Errorf("init named the value and did not say what to do about it:\n%s", out)
	}
}

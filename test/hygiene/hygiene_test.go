// The repository must hold no value that is shaped like a credential.
//
// This is a rule about the files, not about the product, and it has now had to
// be learned three times. PR 0 wrote a corpus file of example values and the
// host refused the push. PR 2 wrote a test of the vendor shapes and the host
// refused that too. PR 3 wrote the example token out of the Telegram
// documentation into a test, the push went through, and GitHub secret scanning
// raised an alert against the repository.
//
// Two costs follow every time. The host blocks the work, and a person who
// reads the file cannot tell a made-up key from a real one, so nobody knows
// whether to revoke anything.
//
// The rule is therefore checked by a machine and not by a promise, and it is
// checked with the classifier's own shape rules. A value that this tool would
// call a vendor credential must not be written into this tool's own source.
// Generate it instead, as internal/corpus does.
package hygiene_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ByteFinch-Technologies/secretveil/internal/classify"
	"github.com/ByteFinch-Technologies/secretveil/internal/corpus"
	"github.com/ByteFinch-Technologies/secretveil/internal/shape"
)

// minCandidate is the shortest run of characters worth testing. Every vendor
// shape is longer than this, so a shorter run cannot match one.
const minCandidate = 16

// allowed records what was already in the repository when this test was
// written, keyed by the path and the rule that reads it.
//
// It is keyed that way on purpose, so that no credential-shaped value has to
// be written into this file to silence it. Writing one here would break the
// rule that this test exists to keep.
//
// This is a baseline and not a permission. The guard stops anything new from
// arriving, and the rows below are a list of work to do. Do not add a row for
// new code: generate the value instead, as internal/corpus does.
var allowed = map[string]string{
	// One fixture, "sk-" and a word and sixteen characters, is used as the
	// example secret across the test suite. It is invented and it is not the
	// shape that the vendor issues, which is why no scanner has ever raised it.
	// Our own rule still reads it as one, so it has to go. Replacing it touches
	// eight files and changes what several tests measure, so it is its own
	// change and not a line in this one.
	"internal/migrate/apply_test.go\tvalue-openai-key":       "the shared test fixture. Replace it.",
	"internal/migrate/restore_test.go\tvalue-openai-key":     "the shared test fixture. Replace it.",
	"internal/migrate/rename_test.go\tvalue-openai-key":      "the shared test fixture. Replace it.",
	"internal/runtime/unread_test.go\tvalue-openai-key":      "the shared test fixture. Replace it.",
	"internal/runtime/run_test.go\tvalue-openai-key":         "the shared test fixture. Replace it.",
	"internal/audit/audit_test.go\tvalue-openai-key":         "the shared test fixture. Replace it.",
	"internal/classify/classify_test.go\tvalue-openai-key":   "the shared test fixture. Replace it.",
	"test/adversarial/adversarial_test.go\tvalue-openai-key": "the shared test fixture. Replace it.",
	"docs/how-it-works.html\tvalue-openai-key":               "the same fixture, shown in the document. Replace it.",

	// The classifier's own tests give one example of each vendor shape. These
	// are the rows that PR 2 could not remove, because a test of a shape rule
	// needs a value of that shape. The corpus generator answers this, and
	// TestEveryVendorShapeIsRecognised already reads from it.
	"internal/classify/classify_test.go\tvalue-aws-access-key-id": "a shape example. Read it from internal/corpus.",
	"internal/classify/classify_test.go\tvalue-stripe-live-key":   "a shape example. Read it from internal/corpus.",
	"internal/classify/classify_test.go\tvalue-slack-token":       "a shape example. Read it from internal/corpus.",
	"internal/classify/classify_test.go\tvalue-github-token":      "a shape example. Read it from internal/corpus.",
	"internal/classify/classify_test.go\tvalue-google-api-key":    "a shape example. Read it from internal/corpus.",
	"internal/classify/classify_test.go\tvalue-private-key":       "a shape example. Read it from internal/corpus.",
	"internal/classify/name_test.go\tvalue-github-token":          "a shape example. Read it from internal/corpus.",
	"internal/classify/name_test.go\tvalue-jwt":                   "a shape example. Read it from internal/corpus.",
}

// candidateChars are the characters a credential is made of. A run of these is
// pulled out of the file and offered to the classifier whole.
const candidateChars = "" +
	"abcdefghijklmnopqrstuvwxyz" +
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
	"0123456789" +
	"_-+/=."

func isCandidateChar(c byte) bool { return strings.IndexByte(candidateChars, c) >= 0 }

func TestNoCredentialShapedValueIsWrittenInThisRepository(t *testing.T) {
	root := filepath.Join("..", "..")
	var read int
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "dist":
				return fs.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() > 4<<20 {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		read++
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		reported := map[string]bool{}
		for _, c := range candidates(string(b)) {
			// The key is bland, so only a value rule can fire. A name rule
			// would say nothing about the shape of the value.
			d := classify.Classify("X", c)
			if !strings.HasPrefix(d.Rule, "value-") {
				continue
			}
			if _, ok := allowed[rel+"\t"+d.Rule]; ok {
				continue
			}
			// One line for each pair of file and rule. A fixture that a file
			// repeats fifteen times is one thing to fix, not fifteen.
			if reported[d.Rule] {
				continue
			}
			reported[d.Rule] = true
			t.Errorf("%s holds a value that rule %q reads as a credential.\n"+
				"Generate it, as internal/corpus does. Do not add a row to allowed for new code.",
				rel, d.Rule)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if read < 40 {
		t.Fatalf("only %d files were read, so this test proves nothing. Check the walk.", read)
	}
	t.Logf("%d files hold no credential-shaped value", read)
}

// candidates pulls every run of credential characters out of a file, and also
// every line holding a PEM header, which carries a space and so is not a run.
func candidates(body string) []string {
	var out []string
	start := -1
	for i := 0; i <= len(body); i++ {
		if i < len(body) && isCandidateChar(body[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= minCandidate {
			out = append(out, body[start:i])
		}
		start = -1
	}
	// A PEM header carries a space, so no run holds it. The header alone is
	// not a credential: a test that names the format writes one and there is
	// nothing behind it. It counts only when key material follows it.
	//
	// The material may sit on the next line or straight after the header on
	// the same line. A first version of this looked only for a newline, and
	// the control below caught it: every one-line private key went unseen.
	for i := 0; i+len(pemStart) < len(body); i++ {
		if !strings.HasPrefix(body[i:], pemStart) {
			continue
		}
		after := body[i+len(pemStart):]
		end := strings.Index(after, "-----")
		if end < 0 || end > 40 {
			continue
		}
		rest := after[end+5:]
		if len(rest) > 400 {
			rest = rest[:400]
		}
		// The body must read as key material and not as words. A test that
		// needs a PEM block may write one, so long as what sits inside it
		// says plainly that it is a fixture.
		if material := longestRunText(rest); shape.LooksRandom(material) {
			out = append(out, body[i:i+len(pemStart)+end+5]+material)
		}
	}
	return out
}

// pemStart opens every private key block.
const pemStart = "-----BEGIN "

// longestRunText returns the longest run of credential characters in a text.
// Key material is one long run. A comment and a line of Go source are not.
func longestRunText(text string) string {
	best, start, n := "", 0, 0
	for i := 0; i <= len(text); i++ {
		if i < len(text) && isCandidateChar(text[i]) {
			if n == 0 {
				start = i
			}
			n++
			continue
		}
		if n > len(best) {
			best = text[start:i]
		}
		n = 0
	}
	return best
}

// TestTheGuardCatchesAKnownShape is the negative control.
//
// A guard that only ever reports nothing is indistinguishable from a guard
// that does not work. This one builds a file in memory that holds a vendor
// credential, and asserts that the same two steps the walk uses find it.
//
// The values are generated, so this test writes no credential-shaped literal
// either. That is the rule it exists to keep.
func TestTheGuardCatchesAKnownShape(t *testing.T) {
	rows := corpus.Generate()
	const prefix = "the value carries the "
	checked := 0
	for _, r := range rows {
		if !strings.HasPrefix(r.Note, prefix) {
			continue
		}
		// The value is put where one would really sit: inside a quoted string
		// in a line of Go source, with other text around it.
		body := "package x\n\nconst fixture = \"" + r.Value + "\" // a fixture\n"
		found := false
		for _, c := range candidates(body) {
			if strings.HasPrefix(classify.Classify("X", c).Rule, "value-") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("the guard does not find a value of the %s shape written into a source file",
				strings.TrimSuffix(strings.TrimPrefix(r.Note, prefix), " shape"))
		}
		checked++
	}
	if checked < 20 {
		t.Fatalf("only %d shapes were offered to the guard, so this control proves little", checked)
	}
	t.Logf("the guard finds a written value of each of %d vendor shapes", checked)
}

// TestTheGuardIgnoresAFixtureThatSaysSo checks the other side. A test that
// needs a PEM block may write one, so long as what sits inside it reads as
// words and not as key material.
func TestTheGuardIgnoresAFixtureThatSaysSo(t *testing.T) {
	body := "KEY=\"-----BEGIN PRIVATE KEY-----\n" +
		"this-is-not-a-key-it-is-a-fixture-for-a-test\n" +
		"-----END PRIVATE KEY-----\"\n"
	for _, c := range candidates(body) {
		if rule := classify.Classify("X", c).Rule; strings.HasPrefix(rule, "value-") {
			t.Errorf("the guard reads a named fixture as a credential, by rule %q", rule)
		}
	}
}

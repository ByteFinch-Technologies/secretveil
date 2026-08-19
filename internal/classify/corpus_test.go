package classify_test

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/ByteFinch-Technologies/secretveil/internal/classify"
	"github.com/ByteFinch-Technologies/secretveil/internal/corpus"
)

var update = flag.Bool("update", false, "rewrite the corpus and the golden decisions")

const goldenFile = "testdata/decisions.golden"

// maxMiss is the share of secret rows that the classifier is still allowed to
// leak. It is a ratchet. Lower it whenever a rule improves and never raise it.
//
// The rules of v0.1.0 measured 31.2%, and that number is the reason this whole
// package exists. The name rules took it to 3.0%. The target is 0, and every
// value that still leaks is an entropy rule and not a name or a shape. The
// entropy rule of PR 3 took it to 0. The limit is not written as 0, because a
// corpus that grows may add one row that no rule reaches, and the build must
// then report a number and not stop the work of everybody.
const maxMiss = 0.001

// The corpus is generated and never committed.
//
// Every value in it has the shape of a real credential, because a value that
// does not look like a credential measures nothing. A file of such values in a
// public repository is wrong twice over: the host blocks the push, and a
// reader cannot tell a made-up key from a real one. So the generator is the
// artefact under review, and the rows live only in memory.
//
// Two tests hold that up. One proves the generator gives the same rows every
// time, which is what lets the golden decisions below be a stable diff. The
// other walks the whole repository and proves that no corpus value is stored
// in any file of it.

// TestTheCorpusIsDeterministic proves the rows do not move between runs.
//
// The golden decisions are one line per row in generated order. A generator
// that shuffled would turn every rule change into an unreadable diff.
func TestTheCorpusIsDeterministic(t *testing.T) {
	first := corpus.Marshal(corpus.Generate())
	second := corpus.Marshal(corpus.Generate())
	if first != second {
		t.Fatal("two calls to corpus.Generate gave different rows.\n" +
			"The generator must take every random choice from corpus.Seed.")
	}
	rows := corpus.Generate()
	c := corpus.Counts(rows)
	t.Logf("the corpus holds %d secret rows and %d open rows", c[corpus.Secret], c[corpus.Open])
	if c[corpus.Secret] < 600 {
		t.Errorf("the corpus holds %d secret rows and the floor is 600", c[corpus.Secret])
	}
	if c[corpus.Open] < 400 {
		t.Errorf("the corpus holds %d open rows and the floor is 400", c[corpus.Open])
	}
}

// TestNoCorpusValueIsStoredInTheRepository is the guard that keeps a
// credential-shaped string out of the tree.
//
// It reads every file of the repository and looks for every part that the
// corpus marks sensitive. A person who pastes a corpus row into a test
// fixture, a document or a golden file fails this test. A person who pastes a
// real credential is not caught here, but the habit that leads to it is.
func TestNoCorpusValueIsStoredInTheRepository(t *testing.T) {
	needles := longSensitiveParts()
	if len(needles) < 300 {
		t.Fatalf("only %d parts are long enough to search for, so this test proves little", len(needles))
	}

	root := filepath.Join("..", "..")
	var read int
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
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
		if key, found := findNeedle(string(b), needles); found {
			t.Errorf("%s holds a corpus value for %s.\n"+
				"The corpus is generated and must never be written to a file in this repository.", path, key)
			return fs.SkipAll
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if read < 40 {
		t.Errorf("only %d files were read, so this test proves nothing. Check the walk.", read)
	}
	t.Logf("%d files hold none of the %d corpus values", read, len(needles))
}

// TestTheSearchFindsAPlantedValue proves the test above can fail.
//
// A search that finds nothing passes for two reasons, and only one of them is
// good. This one plants a corpus value in a piece of text and asks for it back.
func TestTheSearchFindsAPlantedValue(t *testing.T) {
	needles := longSensitiveParts()
	var planted, key string
	for n, k := range needles {
		planted, key = n, k
		break
	}
	text := "SOME_OTHER_KEY=harmless\nPLANTED=" + planted + "\n"
	got, found := findNeedle(text, needles)
	if !found {
		t.Fatalf("the search did not find a value it was given, so it proves nothing")
	}
	if got != key {
		t.Errorf("the search named %s and the planted value belongs to %s", got, key)
	}
	if _, found := findNeedle("nothing to see here\n", needles); found {
		t.Error("the search found a value in text that holds none")
	}
}

// longSensitiveParts collects every part of the corpus that is long enough to
// search a file for. The key of the map is the value and the value is the name
// it belongs to, so a report can say which row was stored.
func longSensitiveParts() map[string]string {
	needles := map[string]string{}
	for _, r := range corpus.Generate() {
		for _, s := range r.Sensitive {
			// A short part gives a false report. "letmein" is a corpus
			// password and it is also an ordinary word that a document may
			// use. Every credential-shaped value is far longer than this.
			if len(s) >= 20 {
				needles[s] = r.Key
			}
		}
	}
	return needles
}

// findNeedle reports the first corpus value that the text holds.
func findNeedle(text string, needles map[string]string) (string, bool) {
	for needle, key := range needles {
		if strings.Contains(text, needle) {
			return key, true
		}
	}
	return "", false
}

// TestCorpusDecisionsGolden records the decision for every row.
//
// The file is the review surface. A change to a rule shows up here as a diff,
// and any line that becomes less safe is marked, so a reviewer cannot miss it.
func TestCorpusDecisionsGolden(t *testing.T) {
	rows := loadCorpus(t)
	got := renderDecisions(rows)
	if *update {
		writeFile(t, goldenFile, got)
		return
	}
	want := readFile(t, goldenFile)
	if got == want {
		return
	}
	t.Errorf("the decisions moved. Read every line marked LESS SAFE before you accept them.\n" +
		"Run: go test ./internal/classify -run TestCorpusDecisionsGolden -update")
	t.Log(lessSafeReport(want, got))
}

// TestVersionRisesWithTheRules ties classify.Version to the golden file.
func TestVersionRisesWithTheRules(t *testing.T) {
	want := readFile(t, goldenFile)
	line := fmt.Sprintf("# classifier version %d", classify.Version)
	if !strings.HasPrefix(want, line+"\n") {
		t.Errorf("the golden decisions were written by classifier version %q and this build is version %d.\n"+
			"Raise classify.Version in the same commit as the rule change, then run:\n"+
			"  go test ./internal/classify -run TestCorpusDecisionsGolden -update",
			strings.SplitN(want, "\n", 2)[0], classify.Version)
	}
}

// TestCorpusMissRate measures how much of the corpus leaks.
//
// A miss is a row labelled secret where a sensitive part survives into the
// text the agent reads. The measurement is printed in full, because the number
// is the point of this package and a reader must be able to see it move.
func TestCorpusMissRate(t *testing.T) {
	rows := loadCorpus(t)
	var secrets, missed int
	byNote := map[string][2]int{}
	var examples []string
	for _, r := range rows {
		if r.Want != corpus.Secret {
			continue
		}
		secrets++
		n := byNote[r.Note]
		n[1]++
		if leaked(r) {
			missed++
			n[0]++
			if len(examples) < 25 {
				examples = append(examples, fmt.Sprintf("  %s=%s -> %s", r.Key, short(r.Value), classify.Classify(r.Key, r.Value).Rule))
			}
		}
		byNote[r.Note] = n
	}
	rate := float64(missed) / float64(secrets)
	t.Logf("%d of %d secret rows leak (%.1f%%)", missed, secrets, rate*100)

	var notes []string
	for n := range byNote {
		notes = append(notes, n)
	}
	sort.Strings(notes)
	for _, n := range notes {
		c := byNote[n]
		if c[0] > 0 {
			t.Logf("  %3d of %3d leak: %s", c[0], c[1], n)
		}
	}
	for _, e := range examples {
		t.Log(e)
	}
	if rate > maxMiss {
		t.Errorf("%.1f%% of the secret rows leak and the ceiling is %.1f%%", rate*100, maxMiss*100)
	}
}

// TestNoConfigRowIsVeiled measures the other direction. A false veil is noise
// and not a breach, so this is a report and not yet a gate.
func TestNoConfigRowIsVeiled(t *testing.T) {
	rows := loadCorpus(t)
	var open, veiled int
	var examples []string
	for _, r := range rows {
		if r.Want != corpus.Open {
			continue
		}
		open++
		if d := classify.Classify(r.Key, r.Value); d.Class != classify.Open {
			veiled++
			if len(examples) < 25 {
				examples = append(examples, fmt.Sprintf("  %s=%s -> %s (%s)", r.Key, short(r.Value), d.Class, d.Rule))
			}
		}
	}
	t.Logf("%d of %d open rows are veiled (%.1f%%)", veiled, open, float64(veiled)/float64(open)*100)
	for _, e := range examples {
		t.Log(e)
	}
}

// ------------------------------------------------------------------ helpers

// leaked reports whether any sensitive part of a row survives into the text
// the agent reads. It tests the projected text and not the class, because a
// composite can be Partial and still leave a credential in the clear.
func leaked(r corpus.Row) bool {
	seen := classify.Project(r.Value, classify.Classify(r.Key, r.Value))
	for _, s := range r.Sensitive {
		if strings.Contains(seen, s) {
			return true
		}
	}
	return false
}

func loadCorpus(t *testing.T) []corpus.Row {
	t.Helper()
	return corpus.Generate()
}

// renderDecisions writes one line per row. The class, the rule and whether the
// row leaks are all on the line, so a diff shows the change and its effect.
func renderDecisions(rows []corpus.Row) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# classifier version %d\n", classify.Version)
	b.WriteString("# The decision for every corpus row. Regenerate with -update.\n")
	b.WriteString("# want key class rule result\n")
	for _, r := range rows {
		d := classify.Classify(r.Key, r.Value)
		result := "held"
		switch {
		case r.Want == corpus.Secret && leaked(r):
			result = "LEAKS"
		case r.Want == corpus.Open && d.Class != classify.Open:
			result = "false-veil"
		}
		fmt.Fprintf(&b, "%s\t%s\t%s\t%s\t%s\n", r.Want, r.Key, d.Class, d.Rule, result)
	}
	return b.String()
}

// lessSafeReport names every line that moved towards showing more of a value.
func lessSafeReport(oldText, newText string) string {
	rank := map[string]int{"veiled": 2, "partial": 1, "open": 0}
	oldLines := strings.Split(oldText, "\n")
	newLines := strings.Split(newText, "\n")
	var b strings.Builder
	worse, better, n := 0, 0, 0
	for i := range newLines {
		if i >= len(oldLines) || strings.HasPrefix(newLines[i], "#") || newLines[i] == "" {
			continue
		}
		o, w := strings.Split(oldLines[i], "\t"), strings.Split(newLines[i], "\t")
		if len(o) != 5 || len(w) != 5 || o[1] != w[1] {
			continue
		}
		switch {
		case o[4] != "LEAKS" && w[4] == "LEAKS", rank[w[2]] < rank[o[2]]:
			worse++
			if n < 40 {
				n++
				fmt.Fprintf(&b, "LESS SAFE  %s  %s/%s -> %s/%s\n", w[1], o[2], o[4], w[2], w[4])
			}
		case o[4] == "LEAKS" && w[4] != "LEAKS", rank[w[2]] > rank[o[2]]:
			better++
		}
	}
	fmt.Fprintf(&b, "\n%d lines became less safe and %d became safer.\n", worse, better)
	return b.String()
}

func short(v string) string {
	if len(v) <= 42 {
		return v
	}
	return v[:39] + "..."
}

func readFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("%v\nRun the test again with -update to write the file.", err)
	}
	return string(b)
}

func writeFile(t *testing.T, name, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s", name)
}

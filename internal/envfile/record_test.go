package envfile

import "testing"

// A .env file may name the same key twice. A loader reads the last assignment,
// so the first one is dead text, but it still holds whatever the developer put
// there. A caller that must reach every record writes through the record and
// not through the key.

func TestLineSetWritesOnlyThatRecord(t *testing.T) {
	f := Parse([]byte("KEY=first\nOTHER=x\nKEY=second\n"))
	lines := f.Assignments()
	if len(lines) != 3 {
		t.Fatalf("the file has %d assignment(s), want three", len(lines))
	}
	if !lines[0].Set("sv://one") {
		t.Fatal("the first record could not be written")
	}
	if !lines[2].Set("sv://two") {
		t.Fatal("the last record could not be written")
	}
	want := "KEY=sv://one\nOTHER=x\nKEY=sv://two\n"
	if got := string(f.Bytes()); got != want {
		t.Fatalf("the file reads\n%q\nwant\n%q", got, want)
	}
}

// Set by key writes the last record only. This is what a loader reads, and it
// is correct for a caller that wants the live value. It is a trap for a caller
// that must reach every record, and the test states the behaviour so that a
// reader of the code does not have to guess it.
func TestFileSetWritesTheLastRecordOnly(t *testing.T) {
	f := Parse([]byte("KEY=first\nKEY=second\n"))
	if !f.Set("KEY", "sv://key") {
		t.Fatal("the key could not be written")
	}
	want := "KEY=first\nKEY=sv://key\n"
	if got := string(f.Bytes()); got != want {
		t.Fatalf("the file reads\n%q\nwant\n%q", got, want)
	}
}

func TestLineSetRefusesARecordThatIsNotAnAssignment(t *testing.T) {
	f := Parse([]byte("# a comment\nKEY=value\n"))
	if f.Lines[0].Set("x") {
		t.Fatal("a comment must not take a value")
	}
	if f.Lines[0].SetInline("x") {
		t.Fatal("a comment must not take an inline comment")
	}
	if got := string(f.Bytes()); got != "# a comment\nKEY=value\n" {
		t.Fatalf("the file changed: %q", got)
	}
}

// A record with a multi-line quoted value covers more than one physical line.
// The index of a record is not the number a person reads in an editor, and a
// message that names a line must use the number the person can find.
func TestPhysicalLineCountsAMultiLineValue(t *testing.T) {
	f := Parse([]byte("A=1\nPEM=\"one\ntwo\nthree\"\nB=2\n"))
	for index, want := range map[int]int{0: 1, 1: 2, 2: 5} {
		if got := f.PhysicalLine(index); got != want {
			t.Fatalf("record %d starts at line %d, want %d", index, got, want)
		}
	}
}

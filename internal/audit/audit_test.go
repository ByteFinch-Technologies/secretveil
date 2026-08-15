package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// project makes a root that already has a .secretveil directory.
func project(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".secretveil"), 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestWriteAndRead(t *testing.T) {
	root := project(t)
	log := New(root)
	code := 42

	want := []Record{
		{Event: EventRun, Caller: "agent", Reason: "CLAUDECODE is set",
			Command: []string{"npm", "run", "dev"}, Refs: []string{"api_key"}, ExitCode: &code},
		{Event: EventRefused, Caller: "agent", Command: []string{"bash", "-c", "printenv"},
			Detail: "it is in the deny list"},
		{Event: EventReveal, Caller: "human", Refs: []string{"api_key"}},
	}
	for _, r := range want {
		if err := log.Write(r); err != nil {
			t.Fatal(err)
		}
	}

	got, err := Read(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d records, want %d", len(got), len(want))
	}
	for i := range got {
		if got[i].Event != want[i].Event || got[i].Caller != want[i].Caller {
			t.Errorf("record %d is %+v, want event %s from %s", i, got[i], want[i].Event, want[i].Caller)
		}
		if got[i].Time.IsZero() {
			t.Errorf("record %d has no time", i)
		}
	}
	if got[0].ExitCode == nil || *got[0].ExitCode != 42 {
		t.Errorf("the exit code did not survive the round trip: %+v", got[0].ExitCode)
	}
}

// TestTheLogIsAppendOnly guards the point of the file. A second logger must add
// to the record, not start it again.
func TestTheLogIsAppendOnly(t *testing.T) {
	root := project(t)
	for i := 0; i < 5; i++ {
		if err := New(root).Write(Record{Event: EventRun, Caller: "agent"}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := Read(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Fatalf("got %d records, want 5. The log was rewritten instead of appended", len(got))
	}
}

// TestEveryLineIsOneRecord keeps the file readable by an ordinary line tool.
func TestEveryLineIsOneRecord(t *testing.T) {
	root := project(t)
	log := New(root)
	// A detail with a newline in it must not become two lines.
	if err := log.Write(Record{Event: EventRefused, Detail: "first line\nsecond line"}); err != nil {
		t.Fatal(err)
	}
	if err := log.Write(Record{Event: EventRun}); err != nil {
		t.Fatal(err)
	}

	body, err := os.ReadFile(filepath.Join(root, ".secretveil", FileName))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(body), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2:\n%s", len(lines), body)
	}
	for i, line := range lines {
		var r Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Errorf("line %d is not one record: %v", i, err)
		}
	}
}

func TestADamagedLineIsSkipped(t *testing.T) {
	root := project(t)
	path := filepath.Join(root, ".secretveil", FileName)
	body := `{"time":"2026-08-15T10:00:00Z","event":"run","caller":"agent"}
this line is not JSON at all
{"time":"2026-08-15T10:00:01Z","event":"refused","caller":"agent"}

`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Read(root)
	if err != nil {
		t.Fatalf("a damaged line stopped the whole log: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d records, want the 2 good ones", len(got))
	}
}

// TestAProjectWithNoDirectoryWritesNothing. A log file is not a reason to make
// a directory in somebody's project.
func TestAProjectWithNoDirectoryWritesNothing(t *testing.T) {
	root := t.TempDir()
	if err := New(root).Write(Record{Event: EventRun}); err != nil {
		t.Fatalf("the write reported an error, and it should do nothing quietly: %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("the logger made %d entries in a project that has no .secretveil directory", len(entries))
	}
	got, err := Read(root)
	if err != nil || got != nil {
		t.Errorf("Read gave %v, %v. A missing log is not an error", got, err)
	}
}

// TestTheLogIsPrivate. The file holds the command lines of the developer.
func TestTheLogIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows does not use these permission bits")
	}
	root := project(t)
	if err := New(root).Write(Record{Event: EventRun}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(root, ".secretveil", FileName))
	if err != nil {
		t.Fatal(err)
	}
	if mode := fi.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("the log is %04o, and every other user on the machine can read it", mode)
	}
}

func TestRedact(t *testing.T) {
	const long = "sk-live-Q9xR2mVn7pLwT4aZ8bC1dE3fG5hJ7kL9mN0pQ2rS4tU6"

	cases := []struct {
		name string
		in   []string
		want []string
	}{{
		name: "an ordinary command is left alone",
		in:   []string{"npm", "run", "dev"},
		want: []string{"npm", "run", "dev"},
	}, {
		name: "the value after a credential flag goes",
		in:   []string{"login", "--password", "hunter2"},
		want: []string{"login", "--password", "[hidden]"},
	}, {
		name: "a flag joined with an equals sign keeps the flag",
		in:   []string{"login", "--api-key=abc123"},
		want: []string{"login", "--api-key=[hidden]"},
	}, {
		name: "a short flag counts too",
		in:   []string{"psql", "-password", "hunter2"},
		want: []string{"psql", "-password", "[hidden]"},
	}, {
		name: "a long run with no space goes, flag or not",
		in:   []string{"curl", long},
		want: []string{"curl", "[hidden]"},
	}, {
		name: "a long argument with a space stays, because it is prose",
		in:   []string{"git", "commit", "-m", "this is a long message about what changed today"},
		want: []string{"git", "commit", "-m", "this is a long message about what changed today"},
	}, {
		name: "the flag name is not hidden, only its value",
		in:   []string{"curl", "-H", "--token", "abc"},
		want: []string{"curl", "-H", "--token", "[hidden]"},
	}, {
		name: "an empty command gives nothing",
		in:   nil,
		want: nil,
	}, {
		// This is the shape the doc comment on Redact names, and it is the one
		// a whole argument test lets through, because the argument has spaces.
		name: "a bearer token inside a header goes",
		in:   []string{"curl", "-H", "Authorization: Bearer " + long, "https://api.example.com"},
		want: []string{"curl", "-H", "Authorization: Bearer [hidden]", "https://api.example.com"},
	}, {
		name: "a short value in a header goes too, because the name says what it is",
		in:   []string{"curl", "-H", "X-Api-Key: abc123"},
		want: []string{"curl", "-H", "X-Api-Key: [hidden]"},
	}, {
		// A word that only holds the letters of a credential word is not one.
		name: "a sentence about a keyboard is left alone",
		in:   []string{"git", "commit", "-m", "fix the keyboard trap and the authority check"},
		want: []string{"git", "commit", "-m", "fix the keyboard trap and the authority check"},
	}, {
		// The guess is deliberately wide, so it costs an ordinary sentence that
		// uses a credential word. A log entry is worth less than a leak.
		name: "a sentence that uses a credential word loses its tail",
		in:   []string{"git", "commit", "-m", "rotate the token before friday"},
		want: []string{"git", "commit", "-m", "rotate the token [hidden] [hidden]"},
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Redact(c.in)
			if len(got) != len(c.want) {
				t.Fatalf("got %q, want %q", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("argument %d is %q, want %q", i, got[i], c.want[i])
				}
			}
		})
	}
}

// TestWriteRedactsTheCommand proves the wiring. Redact is only useful if Write
// calls it.
func TestWriteRedactsTheCommand(t *testing.T) {
	root := project(t)
	const value = "sk-live-Q9xR2mVn7pLwT4aZ8bC1dE3fG5hJ7kL9mN0pQ2rS4tU6"

	if err := New(root).Write(Record{
		Event:   EventRefused,
		Command: []string{"curl", "-H", "Authorization: Bearer " + value, "--token", value},
	}); err != nil {
		t.Fatal(err)
	}

	body, err := os.ReadFile(filepath.Join(root, ".secretveil", FileName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), value) {
		t.Fatalf("the log holds a value that looks like a secret:\n%s", body)
	}
}

// TestTheTimeIsUTC keeps two machines in one team comparable.
func TestTheTimeIsUTC(t *testing.T) {
	root := project(t)
	if err := New(root).Write(Record{Event: EventRun}); err != nil {
		t.Fatal(err)
	}
	got, err := Read(root)
	if err != nil || len(got) != 1 {
		t.Fatalf("got %v, %v", got, err)
	}
	if _, offset := got[0].Time.Zone(); offset != 0 {
		t.Errorf("the time is written with an offset of %d seconds, and it should be UTC", offset)
	}
	if d := time.Since(got[0].Time); d < 0 || d > time.Minute {
		t.Errorf("the time is %v away from now", d)
	}
}

// TestAGivenTimeIsKept lets a caller record when something really happened.
func TestAGivenTimeIsKept(t *testing.T) {
	root := project(t)
	when := time.Date(2026, 8, 15, 9, 30, 0, 0, time.UTC)
	if err := New(root).Write(Record{Time: when, Event: EventRun}); err != nil {
		t.Fatal(err)
	}
	got, err := Read(root)
	if err != nil || len(got) != 1 {
		t.Fatalf("got %v, %v", got, err)
	}
	if !got[0].Time.Equal(when) {
		t.Errorf("got %v, want %v", got[0].Time, when)
	}
}

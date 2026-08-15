// Package audit keeps a local record of every time a secret was used or
// refused.
//
// The log answers one question after the fact: what did the agent do while I
// was not watching? It stays on the machine. Nothing is sent anywhere.
//
// The log never holds a secret value. It holds the reference name, which is a
// label, and the shape of what happened. A log that holds values would be one
// more plaintext file to protect, and the whole product exists to remove those.
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FileName is the log inside the .secretveil directory.
const FileName = "audit.log"

// Event is the kind of thing that happened.
type Event string

const (
	// EventRun is a child process that started with resolved values.
	EventRun Event = "run"
	// EventRefused is a command that the policy stopped.
	EventRefused Event = "refused"
	// EventReveal is a plaintext value that a person asked to see.
	EventReveal Event = "reveal"
	// EventInit is a migration.
	EventInit Event = "init"
	// EventRestore is a migration that was undone.
	EventRestore Event = "restore"
	// EventWrite is a value that went into the store.
	EventWrite Event = "write"
	// EventDelete is a value that left the store.
	EventDelete Event = "delete"
)

// Record is one line in the log.
type Record struct {
	Time   time.Time `json:"time"`
	Event  Event     `json:"event"`
	Caller string    `json:"caller"`
	// Reason says which detection rule named the caller.
	Reason string `json:"reason,omitempty"`
	// Command is the program and its arguments. It is the command line, so it
	// can hold anything the caller typed. See Redact.
	Command []string `json:"command,omitempty"`
	// Refs names the secrets involved. A name is a label and not a value.
	Refs []string `json:"refs,omitempty"`
	// Detail is a short free text note.
	Detail string `json:"detail,omitempty"`
	// ExitCode is the exit code of a child process.
	ExitCode *int `json:"exit_code,omitempty"`
}

// Logger appends records to the log of one project.
type Logger struct {
	path string
	// off is true when the project has no .secretveil directory. Then the log
	// does nothing, because a log file is not a reason to make a directory in
	// somebody's project.
	off bool
}

// New returns a logger for a project.
func New(root string) *Logger {
	dir := filepath.Join(root, ".secretveil")
	if _, err := os.Stat(dir); err != nil {
		return &Logger{off: true}
	}
	return &Logger{path: filepath.Join(dir, FileName)}
}

// Write appends one record.
//
// A failure to write the log is returned but it is not fatal to the caller. A
// full disk must not stop a developer from running their program.
func (l *Logger) Write(r Record) error {
	if l.off {
		return nil
	}
	if r.Time.IsZero() {
		r.Time = time.Now().UTC()
	}
	r.Command = Redact(r.Command)

	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(body, '\n'))
	return err
}

// Redact removes what looks like a secret from a command line before it is
// written down.
//
// A command line is not safe to log. A developer types
// "curl -H 'Authorization: Bearer sk-live-...'" and the value is now in the
// log. This is a guess and not a proof, so it is deliberately wide: anything
// that follows a flag whose name sounds like a credential goes, and so does any
// long run of characters with no space in it.
func Redact(args []string) []string {
	if len(args) == 0 {
		return nil
	}
	out := make([]string, len(args))
	hide := false
	for i, a := range args {
		switch {
		case hide:
			out[i] = "[hidden]"
			hide = false
		case looksLikeSecretFlag(a):
			out[i] = a
			hide = true
		default:
			out[i] = redactInside(a)
		}
		// A flag joined to its value with an equals sign hides the value only.
		if j := strings.IndexByte(out[i], '='); j > 0 && looksLikeSecretFlag(out[i][:j]) {
			out[i] = out[i][:j] + "=[hidden]"
			hide = false
		}
	}
	return out
}

// redactInside hides what looks like a credential inside one argument.
//
// A whole argument is not the unit that matters. A developer writes
//
//	curl -H "Authorization: Bearer sk-live-..."
//
// and the credential is one word in the middle of an argument that holds
// spaces. A test on the whole argument sees the spaces and lets it through, so
// each word is tested on its own.
//
// A word that names a credential arms the rest of the argument. Every word
// after it is hidden. The word itself stays, because "Authorization: Bearer
// [hidden]" tells the reader what happened and "[hidden]" alone does not.
func redactInside(a string) string {
	var b strings.Builder
	changed, armed := false, false

	for i := 0; i < len(a); {
		// The run of spaces before the word is copied as it is, so the
		// argument keeps its shape.
		j := i
		for j < len(a) && isSpace(a[j]) {
			j++
		}
		b.WriteString(a[i:j])
		i = j
		for j < len(a) && !isSpace(a[j]) {
			j++
		}
		if j == i {
			break
		}

		word := a[i:j]
		switch {
		case armsRedaction(word):
			armed = true
			b.WriteString(word)
		case armed, len(word) > 40:
			b.WriteString("[hidden]")
			changed = true
		default:
			b.WriteString(word)
		}
		i = j
	}

	if !changed {
		return a
	}
	return b.String()
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' }

// armsRedaction reports whether a word names a credential.
//
// The test is narrow on purpose. A word has to be a credential word by itself,
// or be the name of a header, which ends with a colon. A wider test that only
// looked for the letters would hide the rest of any sentence that holds the
// word "keyboard", because "keyboard" holds "key".
func armsRedaction(word string) bool {
	low := strings.ToLower(strings.Trim(word, `:,;"'`))
	for _, w := range secretWords {
		if low == w {
			return true
		}
	}
	if strings.HasSuffix(word, ":") {
		for _, w := range secretWords {
			if strings.Contains(low, w) {
				return true
			}
		}
	}
	return false
}

// secretWords name a flag whose value is usually a credential.
var secretWords = []string{
	"password", "passwd", "secret", "token", "key", "apikey", "api-key",
	"auth", "credential", "bearer", "pass", "pwd",
}

func looksLikeSecretFlag(a string) bool {
	if !strings.HasPrefix(a, "-") {
		return false
	}
	low := strings.ToLower(strings.TrimLeft(a, "-"))
	if i := strings.IndexByte(low, '='); i > 0 {
		low = low[:i]
	}
	for _, w := range secretWords {
		if strings.Contains(low, w) {
			return true
		}
	}
	return false
}

// Read returns every record in the log, oldest first.
func Read(root string) ([]Record, error) {
	body, err := os.ReadFile(filepath.Join(root, ".secretveil", FileName))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Record
	for _, line := range strings.Split(string(body), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var r Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			// A damaged line is skipped. A log that refuses to open is worse
			// than a log with a hole in it.
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

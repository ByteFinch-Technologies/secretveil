// Package audit keeps a local record of every time a secret was used or
// refused.
//
// The log answers one question after the fact: what did the agent do while I
// was not watching? It stays on the machine. Nothing is sent anywhere.
//
// The log holds the reference name, which is a label, and the shape of what
// happened. A log that holds values would be one more plaintext file to
// protect, and the whole product exists to remove those.
//
// A command line is the one field that can carry anything, so it gets two
// controls. Every value that came out of the store is named through Hide and
// removed with certainty. Everything else is a guess, because the log cannot
// know what the words in a command mean. The guess is wide on purpose. See
// Redact.
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ByteFinch-Technologies/secretveil/internal/redact"
	"github.com/ByteFinch-Technologies/secretveil/internal/shape"
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
	// never holds values that must never reach the log. See Hide.
	never []string
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

// Hide names values that must never reach the log.
//
// A command line is guessed at, because the log cannot know what the words in
// it mean. A resolved secret needs no guess: run holds the plaintext of every
// value it took out of the store, so it can name them here and the log removes
// them with certainty. A guess stays in place for everything else.
//
// A value shorter than the filter floor is left out. A short value matches too
// much other text, and a log full of "[hidden]" answers no question.
func (l *Logger) Hide(values map[string]string) {
	for _, v := range values {
		if len(v) >= redact.DefaultMinLen {
			l.never = append(l.never, v)
		}
	}
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
	r.Command = redactWith(r.Command, l.never)

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

// hidden is what stands in the log in place of a value.
const hidden = "[hidden]"

// Redact removes what looks like a secret from a command line before it is
// written down.
//
// A command line is not safe to log. A developer types
// "curl -H 'Authorization: Bearer sk-live-...'" and the value is now in the
// log. This is a guess and not a proof, so it is deliberately wide. Four
// shapes go: a word that follows a flag whose name sounds like a credential,
// the credential inside a URL, a word whose own shape reads as random, and any
// long run of characters with no space in it.
func Redact(args []string) []string { return redactWith(args, nil) }

// redactWith removes the known values and then guesses at the rest.
//
// The known values go first. A certain rule must not lose to a heuristic.
func redactWith(args []string, never []string) []string {
	if len(args) == 0 {
		return nil
	}
	out := make([]string, len(args))
	hide := false
	for i, a := range args {
		for _, v := range never {
			a = strings.ReplaceAll(a, v, hidden)
		}
		switch {
		case hide:
			out[i] = hidden
			hide = false
		case looksLikeSecretFlag(a):
			out[i] = a
			hide = true
		default:
			out[i] = redactInside(a)
		}
		// A flag joined to its value with an equals sign hides the value only.
		if j := strings.IndexByte(out[i], '='); j > 0 && looksLikeSecretFlag(out[i][:j]) {
			out[i] = out[i][:j] + "=" + hidden
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
			b.WriteString(hidden)
			changed = true
		default:
			w, hit := redactWord(word)
			b.WriteString(w)
			changed = changed || hit
		}
		i = j
	}

	if !changed {
		return a
	}
	return b.String()
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' }

// redactWord hides a credential that stands on its own, with no flag to name
// it.
//
// Two shapes reach a command line that way. A URL carries the credential
// inside itself, in the user information or in a query parameter. A bare token
// is typed as a positional argument, and then only its own shape says what it
// is.
func redactWord(word string) (string, bool) {
	if out, hit := hideInURL(word); hit {
		return out, true
	}
	// LooksRandom is the same test that decides whether init veils a value. A
	// value the classifier would call a secret must not stay in the log.
	if shape.LooksRandom(word) {
		return hidden, true
	}
	return word, false
}

// hideInURL hides a credential that sits inside a URL.
//
// Only the value goes. The rest of the URL stays, because
// "postgres://app:[hidden]@db/orders" tells the reader which database the
// command reached, and "[hidden]" alone does not.
func hideInURL(word string) (string, bool) {
	i := strings.Index(word, "://")
	if i < 0 {
		return word, false
	}
	out, hit := word, false

	// The authority runs from after the scheme to the first "/", "?" or "#".
	// Look for the "@" inside the authority only. A later "@" belongs to the
	// path or to the query, and it names no credential.
	//
	// Inside the authority the user information runs to the LAST "@", because
	// a password can hold an "@" of its own. It holds a password only when it
	// also holds a ":".
	rest := out[i+3:]
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	if at := strings.LastIndexByte(rest[:end], '@'); at > 0 {
		if c := strings.IndexByte(rest[:at], ':'); c >= 0 {
			out = out[:i+3] + rest[:c+1] + hidden + rest[at:]
			hit = true
		}
	}

	// A query parameter carries the other form.
	q := strings.IndexByte(out, '?')
	if q < 0 {
		return out, hit
	}
	parts := strings.Split(out[q+1:], "&")
	for k, part := range parts {
		e := strings.IndexByte(part, '=')
		if e <= 0 || !namesCredential(part[:e]) {
			continue
		}
		parts[k] = part[:e+1] + hidden
		hit = true
	}
	return out[:q+1] + strings.Join(parts, "&"), hit
}

// namesCredential reports whether the name of a flag or of a query parameter
// says that its value is a credential.
//
// The test is a containment test, because a name is short and specific.
// "access_token" and "apiKey" both have to match.
func namesCredential(name string) bool {
	low := strings.ToLower(name)
	for _, w := range secretWords {
		if strings.Contains(low, w) {
			return true
		}
	}
	return false
}

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
	name := strings.TrimLeft(a, "-")
	if i := strings.IndexByte(name, '='); i > 0 {
		name = name[:i]
	}
	return namesCredential(name)
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

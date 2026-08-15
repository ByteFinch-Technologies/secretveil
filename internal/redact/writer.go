package redact

import (
	"io"
	"sync"
)

// DefaultPlaceholder returns the text that replaces a secret in the output. It
// is the same handle that the .env file holds, so a reader who sees it in a log
// already knows what it means.
func DefaultPlaceholder(n Needle) string { return "sv://" + n.Ref }

// noRun marks a byte that no needle covers.
const noRun int64 = 0

// Writer removes every needle from the bytes written through it.
//
// It holds back the smallest number of bytes that could still begin a match.
// That number is one less than the longest needle. Every other byte goes out
// at once, so a program that prints a prompt and waits still shows the prompt.
//
// A Writer is safe for use from more than one goroutine, because the runtime
// drives Write from the child process and FlushIdle from a timer.
type Writer struct {
	dst io.Writer
	m   *Matcher
	// Placeholder renders the replacement text. It may be nil, and then
	// DefaultPlaceholder is used.
	Placeholder func(Needle) string

	mu    sync.Mutex
	state int32
	// buf holds the bytes that are not released yet.
	buf []byte
	// owner runs beside buf and holds the needle index that covers each byte.
	owner []int32
	// run runs beside buf as well. Each match gets its own number, so two
	// matches that touch each other stay two matches and produce two
	// placeholders. A byte that no needle covers holds noRun.
	run     []int64
	nextRun int64
	hits    map[string]int
}

// NewWriter returns a Writer that passes its output to dst.
func NewWriter(dst io.Writer, m *Matcher) *Writer {
	return &Writer{dst: dst, m: m, state: rootState, hits: map[string]int{}}
}

// Hits returns the number of times each reference was removed.
func (w *Writer) Hits() map[string]int {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make(map[string]int, len(w.hits))
	for k, v := range w.hits {
		out[k] = v
	}
	return out
}

// Held returns the number of bytes the Writer is holding back. A test uses it
// to prove the filter does not grow without a limit.
func (w *Writer) Held() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.buf)
}

func (w *Writer) Write(p []byte) (int, error) {
	if w.m == nil || w.m.Empty() {
		return w.dst.Write(p)
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	for i := 0; i < len(p); i++ {
		c := p[i]
		w.buf = append(w.buf, c)
		w.owner = append(w.owner, -1)
		w.run = append(w.run, noRun)
		w.state = w.m.Step(w.state, c)

		if id, length, ok := w.m.Match(w.state); ok {
			start := len(w.buf) - length
			if start < 0 {
				// This cannot happen while the hold back window is at least
				// one byte shorter than the longest needle. The guard keeps a
				// future change from writing past the start of the buffer.
				start = 0
			}
			w.nextRun++
			for k := start; k < len(w.buf); k++ {
				w.owner[k] = id
				w.run[k] = w.nextRun
			}
		}
	}

	if err := w.release(w.safeLimit()); err != nil {
		return 0, err
	}
	return len(p), nil
}

// safeLimit returns the number of leading bytes that no future match can
// reach. A future match ends after the current end and is no longer than the
// longest needle, so it cannot start before that point.
func (w *Writer) safeLimit() int {
	return len(w.buf) - (w.m.MaxLen() - 1)
}

// idleLimit returns the number of leading bytes that are safe to release while
// the stream is quiet.
//
// It is larger than safeLimit, because the automaton knows the exact length of
// the partial match in hand. That length is the depth of the current state, and
// no later match can start before it. At the root state the depth is zero and
// the whole buffer goes out.
func (w *Writer) idleLimit() int {
	lim := len(w.buf) - w.m.Depth(w.state)
	if lim < 0 {
		lim = 0
	}
	// If every byte that is still held is already known to be part of a
	// secret, release it now. The output shows a placeholder either way, so
	// nothing leaks, and a prompt that ends with a secret still reaches the
	// terminal instead of waiting for input that never comes.
	for k := lim; k < len(w.buf); k++ {
		if w.run[k] == noRun {
			return lim
		}
	}
	return len(w.buf)
}

// wholeRuns pulls the limit back so it never cuts a covered run in half. A run
// that touches the limit can still grow when the next bytes arrive.
func (w *Writer) wholeRuns(lim int) int {
	if lim <= 0 || lim >= len(w.buf) {
		return lim
	}
	if w.run[lim] == noRun {
		return lim
	}
	for lim > 0 && w.run[lim-1] == w.run[lim] {
		lim--
	}
	return lim
}

// release writes the first lim bytes and drops them from the buffer.
func (w *Writer) release(lim int) error {
	lim = w.wholeRuns(lim)
	if lim <= 0 {
		return nil
	}
	if lim > len(w.buf) {
		lim = len(w.buf)
	}

	place := w.Placeholder
	if place == nil {
		place = DefaultPlaceholder
	}

	i := 0
	for i < lim {
		r := w.run[i]
		j := i
		for j < lim && w.run[j] == r {
			j++
		}
		if r == noRun {
			if _, err := w.dst.Write(w.buf[i:j]); err != nil {
				return err
			}
			i = j
			continue
		}
		n := w.m.Needle(w.owner[i])
		if _, err := io.WriteString(w.dst, place(n)); err != nil {
			return err
		}
		w.hits[n.Ref]++
		i = j
	}

	w.buf = append(w.buf[:0], w.buf[lim:]...)
	w.owner = append(w.owner[:0], w.owner[lim:]...)
	w.run = append(w.run[:0], w.run[lim:]...)
	return nil
}

// FlushIdle releases every byte that cannot be part of a later match. Call it
// when the stream has been quiet for a short time, so a prompt that waits for
// an answer still reaches the terminal.
func (w *Writer) FlushIdle() error {
	if w.m == nil || w.m.Empty() {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.release(w.idleLimit())
}

// Close releases everything that is left. Call it once, after the stream ends.
// A byte held back at this point can no longer become part of a match, because
// no more input will arrive.
func (w *Writer) Close() error {
	if w.m == nil || w.m.Empty() {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.release(len(w.buf)); err != nil {
		return err
	}
	w.state = rootState
	return nil
}

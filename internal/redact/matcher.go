// Package redact removes a secret value from a stream of output.
//
// The problem is that output arrives in pieces of any size. A secret can start
// in one piece and end in the next, so a filter that looks at one piece at a
// time will miss it. The filter here holds back the smallest number of bytes
// that could still start a match, and it releases every other byte at once.
//
// The matcher is an Aho-Corasick automaton. It finds every needle in one pass
// over the input, and the cost does not grow with the number of needles.
package redact

import "sort"

// Needle is one string to remove, and the reference that replaces it.
type Needle struct {
	// Pattern is the exact bytes to find.
	Pattern string
	// Ref is the name that goes into the output in place of the pattern.
	Ref string
}

const rootState int32 = 0

type node struct {
	next map[byte]int32
	// fail points at the state for the longest proper suffix of this state
	// that is also a prefix of some needle.
	fail int32
	// depth is the length of the string that reaches this state. It is the
	// number of bytes the filter must hold back while it is in this state.
	depth int32
	// needle is the index of the needle that ends here, or -1.
	needle int32
	// outLink points at the nearest state through the fail chain that ends a
	// needle, or -1.
	outLink int32
}

// Matcher finds every needle in a stream.
type Matcher struct {
	nodes   []node
	needles []Needle
	maxLen  int
}

// NewMatcher builds the automaton. It drops an empty needle. It keeps the
// needles in the order given, so a caller can map a match back to its own
// list by index.
func NewMatcher(needles []Needle) *Matcher {
	m := &Matcher{}
	m.nodes = []node{{next: map[byte]int32{}, fail: rootState, depth: 0, needle: -1, outLink: -1}}

	for _, n := range needles {
		if n.Pattern == "" {
			continue
		}
		id := int32(len(m.needles))
		m.needles = append(m.needles, n)
		if len(n.Pattern) > m.maxLen {
			m.maxLen = len(n.Pattern)
		}

		cur := rootState
		for i := 0; i < len(n.Pattern); i++ {
			c := n.Pattern[i]
			nxt, ok := m.nodes[cur].next[c]
			if !ok {
				nxt = int32(len(m.nodes))
				m.nodes = append(m.nodes, node{
					next:    map[byte]int32{},
					fail:    rootState,
					depth:   m.nodes[cur].depth + 1,
					needle:  -1,
					outLink: -1,
				})
				m.nodes[cur].next[c] = nxt
			}
			cur = nxt
		}
		// If two needles have the same text, the first one wins. That keeps
		// the result stable when a caller adds the same value twice.
		if m.nodes[cur].needle < 0 {
			m.nodes[cur].needle = id
		}
	}

	m.buildFailLinks()
	return m
}

// buildFailLinks fills the fail and outLink fields by breadth first search.
func (m *Matcher) buildFailLinks() {
	queue := make([]int32, 0, len(m.nodes))

	// Depth one states fail to the root.
	for _, s := range sortedKeys(m.nodes[rootState].next) {
		child := m.nodes[rootState].next[s]
		m.nodes[child].fail = rootState
		queue = append(queue, child)
	}

	for i := 0; i < len(queue); i++ {
		cur := queue[i]
		// Set the output link before the children read it.
		f := m.nodes[cur].fail
		if m.nodes[f].needle >= 0 {
			m.nodes[cur].outLink = f
		} else {
			m.nodes[cur].outLink = m.nodes[f].outLink
		}

		for _, c := range sortedKeys(m.nodes[cur].next) {
			child := m.nodes[cur].next[c]
			f := m.nodes[cur].fail
			for {
				if nxt, ok := m.nodes[f].next[c]; ok {
					m.nodes[child].fail = nxt
					break
				}
				if f == rootState {
					m.nodes[child].fail = rootState
					break
				}
				f = m.nodes[f].fail
			}
			queue = append(queue, child)
		}
	}
}

func sortedKeys(mm map[byte]int32) []byte {
	out := make([]byte, 0, len(mm))
	for k := range mm {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Empty reports whether there is nothing to find.
func (m *Matcher) Empty() bool { return len(m.needles) == 0 }

// MaxLen is the length of the longest needle. The filter holds back one byte
// less than this while it waits for more input.
func (m *Matcher) MaxLen() int { return m.maxLen }

// Needles returns the needles the matcher kept.
func (m *Matcher) Needles() []Needle { return m.needles }

// Step advances the automaton by one byte and returns the new state.
func (m *Matcher) Step(state int32, c byte) int32 {
	for {
		if nxt, ok := m.nodes[state].next[c]; ok {
			return nxt
		}
		if state == rootState {
			return rootState
		}
		state = m.nodes[state].fail
	}
}

// Depth returns the number of bytes that reach this state. Those bytes are the
// start of a possible match, so the filter must not release them yet.
func (m *Matcher) Depth(state int32) int { return int(m.nodes[state].depth) }

// Match returns the longest needle that ends at this state, if there is one.
// Every other needle that ends here is a suffix of that one, so the longest
// covers them all.
func (m *Matcher) Match(state int32) (id int32, length int, ok bool) {
	if n := m.nodes[state].needle; n >= 0 {
		return n, int(m.nodes[state].depth), true
	}
	if l := m.nodes[state].outLink; l >= 0 {
		return m.nodes[l].needle, int(m.nodes[l].depth), true
	}
	return 0, 0, false
}

// Needle returns the needle with this index.
func (m *Matcher) Needle(id int32) Needle { return m.needles[id] }

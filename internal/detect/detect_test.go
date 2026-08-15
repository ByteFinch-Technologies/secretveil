package detect

import (
	"strings"
	"testing"
)

// env turns a map into the two shapes the rules need.
func env(pairs map[string]string) (func(string) (string, bool), func() []string) {
	lookup := func(name string) (string, bool) {
		v, ok := pairs[name]
		return v, ok
	}
	environ := func() []string {
		var out []string
		for k, v := range pairs {
			out = append(out, k+"="+v)
		}
		return out
	}
	return lookup, environ
}

func tty(yes bool) func() bool { return func() bool { return yes } }

func TestTheRulesRunInOrder(t *testing.T) {
	cases := []struct {
		name string
		vars map[string]string
		tty  bool
		want Caller
		// reason is a piece of the explanation, so a change in the wording of
		// the rest does not break the test.
		reason string
	}{{
		name:   "the override wins over every other rule",
		vars:   map[string]string{EnvOverride: "human", "CI": "true", "CLAUDECODE": "1"},
		tty:    false,
		want:   Human,
		reason: "says human",
	}, {
		name:   "the override reads a synonym",
		vars:   map[string]string{EnvOverride: "  PIPELINE  "},
		want:   CI,
		reason: "says ci",
	}, {
		// This is the fail closed rule at the top of the list. A typed value
		// nobody knows must not open the door.
		name:   "an override nobody knows is an agent",
		vars:   map[string]string{EnvOverride: "developer"},
		tty:    true,
		want:   Agent,
		reason: "which is not a known caller",
	}, {
		name:   "an empty override is an agent, not a missing override",
		vars:   map[string]string{EnvOverride: ""},
		tty:    true,
		want:   Agent,
		reason: "not a known caller",
	}, {
		name:   "a pipeline marker beats an agent marker",
		vars:   map[string]string{"GITHUB_ACTIONS": "true", "CLAUDECODE": "1"},
		want:   CI,
		reason: "GITHUB_ACTIONS is set",
	}, {
		// A shell that exports CI=false must not turn a human into a pipeline.
		name:   "a pipeline marker set to false does not count",
		vars:   map[string]string{"CI": "false"},
		tty:    true,
		want:   Human,
		reason: "terminal",
	}, {
		name:   "a pipeline marker set to zero does not count",
		vars:   map[string]string{"CI": "0"},
		tty:    true,
		want:   Human,
		reason: "terminal",
	}, {
		name:   "an empty pipeline marker does not count",
		vars:   map[string]string{"CI": ""},
		tty:    true,
		want:   Human,
		reason: "terminal",
	}, {
		// An agent often runs with a terminal attached, so the marker has to
		// beat the terminal test.
		name:   "an agent marker beats a terminal",
		vars:   map[string]string{"CLAUDECODE": "1"},
		tty:    true,
		want:   Agent,
		reason: "CLAUDECODE is set",
	}, {
		name:   "a prefix marker matches any variable under it",
		vars:   map[string]string{"AIDER_MODEL": "gpt"},
		tty:    true,
		want:   Agent,
		reason: "AIDER_MODEL is set",
	}, {
		// A name that only starts the same way is not a marker.
		name:   "a name that is not a prefix marker does not match",
		vars:   map[string]string{"CODEXNOTAMARKER": "1"},
		tty:    true,
		want:   Human,
		reason: "terminal",
	}, {
		name:   "a terminal on both streams is a human",
		vars:   map[string]string{"HOME": "/home/dev"},
		tty:    true,
		want:   Human,
		reason: "terminal",
	}, {
		name:   "no terminal and no marker is an agent",
		vars:   map[string]string{"HOME": "/home/dev"},
		tty:    false,
		want:   Agent,
		reason: "no terminal and no marker",
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lookup, environ := env(c.vars)
			got := detect(lookup, environ, tty(c.tty))
			if got.Caller != c.want {
				t.Errorf("got %s, want %s. The reason was %q", got.Caller, c.want, got.Reason)
			}
			if !strings.Contains(got.Reason, c.reason) {
				t.Errorf("the reason %q does not hold %q", got.Reason, c.reason)
			}
		})
	}
}

// TestTheReasonIsTheSameEveryTime guards the audit log. Two runs of the same
// environment must give the same explanation, or a refusal cannot be checked
// later.
func TestTheReasonIsTheSameEveryTime(t *testing.T) {
	vars := map[string]string{
		"ZED_TERM": "1", "AIDER_MODEL": "x", "CLINE_ID": "y", "AMP_MODE": "z",
	}
	lookup, environ := env(vars)

	first := detect(lookup, environ, tty(false))
	for i := 0; i < 50; i++ {
		if got := detect(lookup, environ, tty(false)); got != first {
			t.Fatalf("run %d gave %+v, and the first run gave %+v", i, got, first)
		}
	}
	// Sorted by name, so the first of these four is the one that is reported.
	if first.Reason != "AIDER_MODEL is set" {
		t.Errorf("got %q, want the first marker in name order", first.Reason)
	}
}

// TestAVeryLongOverrideIsCutShort keeps a long value out of the audit log. The
// value comes from the environment, so its length is not ours to trust.
func TestAVeryLongOverrideIsCutShort(t *testing.T) {
	long := strings.Repeat("x", 500)
	lookup, environ := env(map[string]string{EnvOverride: long})

	got := detect(lookup, environ, tty(true))
	if got.Caller != Agent {
		t.Fatalf("got %s, want agent", got.Caller)
	}
	if len(got.Reason) > 100 {
		t.Errorf("the reason is %d characters long, and it should be cut short", len(got.Reason))
	}
	if !strings.Contains(got.Reason, "...") {
		t.Errorf("the reason %q does not show that it was cut short", got.Reason)
	}
}

func TestCallerName(t *testing.T) {
	for c, want := range map[Caller]string{Agent: "agent", Human: "human", CI: "ci", Caller(99): "agent"} {
		if got := c.String(); got != want {
			t.Errorf("Caller(%d) gave %q, want %q", int(c), got, want)
		}
	}
}

// TestEveryMarkerFires is a table sweep. A marker that is in the list but does
// not work is worse than no marker, because the list says it is covered.
func TestEveryMarkerFires(t *testing.T) {
	for _, m := range ciMarkers {
		t.Run("ci/"+m, func(t *testing.T) {
			lookup, environ := env(map[string]string{m: "1"})
			if got := detect(lookup, environ, tty(true)); got.Caller != CI {
				t.Errorf("%s gave %s, want ci", m, got.Caller)
			}
		})
	}
	for _, m := range agentMarkers {
		t.Run("agent/"+m, func(t *testing.T) {
			name := m
			if strings.HasSuffix(m, "_") {
				name = m + "SOMETHING"
			}
			lookup, environ := env(map[string]string{name: "1"})
			if got := detect(lookup, environ, tty(true)); got.Caller != Agent {
				t.Errorf("%s gave %s, want agent", name, got.Caller)
			}
		})
	}
}

// TestDetectReadsTheRealEnvironment proves the wiring. Every other test drives
// the rules with a fake environment, so one test has to call the real thing.
func TestDetectReadsTheRealEnvironment(t *testing.T) {
	t.Setenv(EnvOverride, "human")
	if got := Detect(); got.Caller != Human {
		t.Errorf("got %s, want human", got.Caller)
	}
	t.Setenv(EnvOverride, "agent")
	if got := Detect(); got.Caller != Agent {
		t.Errorf("got %s, want agent", got.Caller)
	}
}

// Package detect answers one question: who started this command?
//
// The answer decides how much power the command gets. A human at a keyboard
// keeps every power the shell gives them. An AI agent gets a narrow path,
// because an agent follows text that a stranger may have written.
//
// REVIEW EVERY QUARTER. The table of markers below is the whole of the
// knowledge in this package, and it goes out of date. A new AI tool ships a new
// marker, and until the marker is in this list that tool falls through to the
// last rule. The last rule is Agent, so a new tool is treated as an agent and
// nothing opens by accident. Add the marker anyway, because a tool that is
// wrongly called an agent gives the developer a refusal they do not understand.
package detect

import (
	"os"
	"sort"
	"strings"

	"golang.org/x/term"
)

// Caller is the kind of program or person that started the command.
type Caller int

const (
	// Agent is an AI tool. It is also the answer when nothing is certain.
	Agent Caller = iota
	// Human is a person at a terminal.
	Human
	// CI is a build pipeline.
	CI
)

func (c Caller) String() string {
	switch c {
	case Human:
		return "human"
	case CI:
		return "ci"
	default:
		return "agent"
	}
}

// EnvOverride names the variable that sets the answer by hand.
const EnvOverride = "SECRETVEIL_CALLER"

// ciMarkers name a build pipeline. A pipeline has no terminal, so without this
// list every pipeline would look like an agent.
var ciMarkers = []string{
	"CI",
	"CONTINUOUS_INTEGRATION",
	"GITHUB_ACTIONS",
	"GITLAB_CI",
	"BUILDKITE",
	"CIRCLECI",
	"TRAVIS",
	"JENKINS_URL",
	"TEAMCITY_VERSION",
	"BITBUCKET_BUILD_NUMBER",
	"TF_BUILD",
}

// agentMarkers name an AI tool. A prefix that ends with an underscore matches
// any variable that starts with it.
//
// Last reviewed 2026-08-15.
var agentMarkers = []string{
	"CLAUDECODE",
	"CLAUDE_CODE",
	"CLAUDE_CODE_ENTRYPOINT",
	"ANTHROPIC_AGENT",
	"CURSOR_TRACE_ID",
	"CURSOR_SESSION_ID",
	"AIDER_",
	"CLINE_",
	"ROO_CODE_",
	"CONTINUE_",
	"WINDSURF_",
	"CODEX_",
	"OPENAI_AGENT",
	"COPILOT_AGENT",
	"GEMINI_CLI",
	"ZED_TERM",
	"OPENCODE_",
	"AMP_",
}

// Result is the answer and the reason for it.
type Result struct {
	Caller Caller
	// Reason says which rule fired. It goes into the audit log, so a refusal
	// can be explained a week later.
	Reason string
}

// Detect returns the kind of caller and the reason.
//
// The rules run in this order, and the first one that fits wins:
//
//  1. SECRETVEIL_CALLER is set. Trust it.
//  2. A pipeline marker is set. The caller is CI.
//  3. An AI tool marker is set. The caller is an agent.
//  4. Standard input and standard output are both a terminal. The caller is a
//     human.
//  5. Anything else is an agent.
//
// Rule 5 is the important one. A command with no terminal and no marker could
// be a script that a developer wrote, or it could be a tool nobody has heard of
// yet. The safe reading of an unknown caller is the one with the least power.
func Detect() Result {
	return detect(os.LookupEnv, os.Environ, terminalPair)
}

// detect is Detect with the environment and the terminal test passed in, so a
// test can drive every rule.
func detect(
	lookup func(string) (string, bool),
	environ func() []string,
	isTTY func() bool,
) Result {
	if raw, ok := lookup(EnvOverride); ok {
		name := strings.ToLower(strings.TrimSpace(raw))
		switch name {
		case "human", "user", "person":
			return Result{Human, EnvOverride + " says human"}
		case "ci", "pipeline", "build":
			return Result{CI, EnvOverride + " says ci"}
		case "agent", "ai", "bot":
			return Result{Agent, EnvOverride + " says agent"}
		default:
			// A value nobody recognises is not a reason to open the door.
			return Result{Agent, EnvOverride + " holds " + quote(name) + ", which is not a known caller"}
		}
	}

	for _, m := range ciMarkers {
		if v, ok := lookup(m); ok && v != "" && v != "false" && v != "0" {
			return Result{CI, m + " is set"}
		}
	}

	if m := firstAgentMarker(environ()); m != "" {
		return Result{Agent, m + " is set"}
	}

	if isTTY() {
		return Result{Human, "standard input and standard output are both a terminal"}
	}

	return Result{Agent, "there is no terminal and no marker, so the caller is treated as an agent"}
}

// firstAgentMarker returns the name of the first AI tool marker in the
// environment, or an empty string.
//
// The names are sorted before the test, so the same environment always names
// the same marker. A reason that changes between two runs is hard to trust.
func firstAgentMarker(env []string) string {
	var names []string
	for _, kv := range env {
		i := strings.IndexByte(kv, '=')
		if i <= 0 {
			continue
		}
		names = append(names, kv[:i])
	}
	sort.Strings(names)

	for _, name := range names {
		for _, m := range agentMarkers {
			if name == m || (strings.HasSuffix(m, "_") && strings.HasPrefix(name, m)) {
				return name
			}
		}
	}
	return ""
}

// terminalPair reports whether both standard input and standard output are a
// terminal.
//
// Both have to be a terminal. A person types into one and reads the other. A
// program that has only one of them is being driven by something else, and that
// something else is the caller this package cares about.
func terminalPair() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

func quote(s string) string {
	if len(s) > 32 {
		s = s[:32] + "..."
	}
	return "\"" + s + "\""
}

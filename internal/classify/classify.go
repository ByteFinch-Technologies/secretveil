// Package classify decides how much of a value an AI agent may see.
//
// A value is veiled unless a rule opens it. The rules run in a fixed order and
// every decision carries the name of the rule that fired, because the init
// table shows that name to the human. A classifier that cannot explain itself
// does not get trusted, and a tool that is not trusted gets switched off.
package classify

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/ByteFinch-Technologies/secretveil/internal/handle"
	"github.com/ByteFinch-Technologies/secretveil/internal/shape"
)

// Class says how much of a value survives into the file the agent reads.
type Class int

const (
	// Open shows the value in full.
	Open Class = iota
	// Partial shows the value with one part replaced by a handle.
	Partial
	// Veiled replaces the whole value with a handle.
	Veiled
)

func (c Class) String() string {
	switch c {
	case Open:
		return "open"
	case Partial:
		return "partial"
	default:
		return "veiled"
	}
}

// Decision is the result for one key and value.
type Decision struct {
	Class Class         `json:"class"`
	Spans []handle.Span `json:"spans,omitempty"`
	Shape shape.Shape   `json:"shape"`
	// Rule names the rule that fired. It is shown to the human.
	Rule string `json:"rule"`
}

var (
	// A credential shape in the value itself. These beat every name rule,
	// because a real key under a public name is a mistake worth catching.
	credentialShapes = []struct {
		re   *regexp.Regexp
		name string
		// keep is the number of leading bytes that stay visible.
		keep int
	}{
		{regexp.MustCompile(`^AKIA[0-9A-Z]{16}$`), "aws-access-key-id", 4},
		{regexp.MustCompile(`^ASIA[0-9A-Z]{16}$`), "aws-temp-key-id", 4},
		{regexp.MustCompile(`^sk-[A-Za-z0-9_\-]{20,}$`), "openai-key", 0},
		{regexp.MustCompile(`^sk_live_[A-Za-z0-9]{20,}$`), "stripe-live-key", 0},
		{regexp.MustCompile(`^sk_test_[A-Za-z0-9]{20,}$`), "stripe-test-key", 0},
		{regexp.MustCompile(`^rk_(live|test)_[A-Za-z0-9]{20,}$`), "stripe-restricted-key", 0},
		{regexp.MustCompile(`^gh[pousr]_[A-Za-z0-9]{36,}$`), "github-token", 0},
		{regexp.MustCompile(`^glpat-[A-Za-z0-9_\-]{20,}$`), "gitlab-token", 0},
		// A vendor lengthens a token and does not rename it. Every count here
		// is a floor, never an exact number, so a longer token still matches.
		{regexp.MustCompile(`^npm_[A-Za-z0-9]{36,}$`), "npm-token", 0},
		{regexp.MustCompile(`^xox[bpsarae]-[0-9A-Za-z\-]{10,}$`), "slack-token", 0},
		{regexp.MustCompile(`^https://hooks\.slack\.com/services/\S+$`), "slack-webhook", 0},
		{regexp.MustCompile(`^https://discord\.com/api/webhooks/\S+$`), "discord-webhook", 0},
		{regexp.MustCompile(`^https://discordapp\.com/api/webhooks/\S+$`), "discord-webhook", 0},
		{regexp.MustCompile(`^AIza[0-9A-Za-z_\-]{35,}$`), "google-api-key", 0},
		{regexp.MustCompile(`^SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}$`), "sendgrid-key", 0},
		// A Twilio signing key identifier. The account identifier starts AC and
		// is public, so it is not here.
		{regexp.MustCompile(`^SK[0-9a-fA-F]{32}$`), "twilio-signing-key", 0},
		{regexp.MustCompile(`^sq0(atp|csp|idp)-[A-Za-z0-9_\-]{20,}$`), "square-token", 0},
		{regexp.MustCompile(`^shp(at|ca|pa|ss)_[0-9a-fA-F]{32,}$`), "shopify-token", 0},
		{regexp.MustCompile(`^key-[0-9a-fA-F]{32}$`), "mailgun-key", 0},
		{regexp.MustCompile(`^eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}$`), "jwt", 0},
		// The algorithm word is not always upper case and PGP writes BLOCK
		// after the words PRIVATE KEY, so both parts are loose.
		{regexp.MustCompile(`(?i)-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z ]*-----`), "private-key", 0},
	}

	// A name that a public bundle already ships. Such a value is not a secret.
	publicPrefix = regexp.MustCompile(`^(NEXT_PUBLIC_|EXPO_PUBLIC_|VITE_|REACT_APP_|PUBLIC_|NUXT_PUBLIC_|GATSBY_)`)

	// Composite forms. Each keeps the readable part and veils one field.
	urlBasicAuth = regexp.MustCompile(`^([a-zA-Z][a-zA-Z0-9+.\-]*://[^:/@\s]+:)([^@/\s]+)(@)`)
	urlQueryCred = regexp.MustCompile(`(?i)([?&](?:token|key|api_key|apikey|password|secret|sig|signature|access_token|auth)=)([^&\s#]+)`)
	adoPassword  = regexp.MustCompile(`(?i)((?:^|;)\s*(?:password|pwd)\s*=\s*)([^;]+)`)
	bearerToken  = regexp.MustCompile(`(?i)^(Bearer\s+)(\S+)$`)

	// A reference to another variable, in either shell form.
	varReference = regexp.MustCompile(`^(\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*)$`)
)

// Classify decides the class of one key and value.
func Classify(key, value string) Decision {
	return dropVeiledSpans(value, classifyValue(key, value))
}

// dropVeiledSpans removes a part of the value that already holds a handle.
//
// init has to be safe to run twice. The second run reads a file that already
// says API_KEY=sv://api_key, and the name rules still say that API_KEY is a
// secret. Without this step the second run would put the text "sv://api_key"
// into the store as if it were the value.
//
// The test is on the text of the value and not on the class, because a name
// rule and a value rule can both fire on a handle, and only the text says
// whether the work was already done.
func dropVeiledSpans(value string, d Decision) Decision {
	if len(d.Spans) == 0 {
		return d
	}
	kept := make([]handle.Span, 0, len(d.Spans))
	dropped := "already-veiled"
	for _, s := range d.Spans {
		if s.Start < 0 || s.End > len(value) || s.Start > s.End {
			continue
		}
		text := value[s.Start:s.End]
		if strings.HasPrefix(text, handle.Scheme) {
			continue
		}
		// The span holds ${OTHER} and not a secret. Storing that text would
		// put the name of a variable into the store as if it were the value,
		// and the real secret would still be wherever OTHER points.
		if varReference.MatchString(text) {
			dropped = "variable-reference"
			continue
		}
		kept = append(kept, s)
	}
	if len(kept) == 0 {
		return Decision{Class: Open, Shape: d.Shape, Rule: dropped}
	}
	d.Spans = kept
	return d
}

// classifyValue holds the rules. Classify wraps it.
func classifyValue(key, value string) Decision {
	sh := shape.Of(value)
	whole := []handle.Span{{Start: 0, End: len(value), Ref: handle.Ref(key)}}

	if strings.TrimSpace(value) == "" {
		return Decision{Class: Open, Shape: sh, Rule: "empty"}
	}

	// Rule 1. The value points at another variable.
	//
	// DB_PASSWORD=${SECRET_ROOT_PW} holds no secret. The secret is whatever
	// SECRET_ROOT_PW holds, and that variable is classified on its own row or
	// comes from the environment. Veiling this one wrote the literal text
	// "${SECRET_ROOT_PW}" into the encrypted store as if it were the password.
	//
	// The reference is deliberately not resolved. Resolving it would put one
	// secret in the store twice under two references, and restore would then
	// have to write the reference back and not the value it stood for.
	if varReference.MatchString(strings.TrimSpace(value)) {
		return Decision{Class: Open, Shape: sh, Rule: "variable-reference"}
	}

	// Rule 2. A composite value keeps its readable part.
	if spans, rule := composite(key, value); len(spans) > 0 {
		return Decision{Class: Partial, Spans: spans, Shape: sh, Rule: rule}
	}

	// Rule 3. A credential shape in the value beats every name rule.
	for _, c := range credentialShapes {
		if !c.re.MatchString(value) {
			continue
		}
		if c.keep > 0 && c.keep < len(value) {
			return Decision{
				Class: Partial,
				Spans: []handle.Span{{Start: c.keep, End: len(value), Ref: handle.Ref(key)}},
				Shape: sh.WithPrefix(value, c.keep),
				Rule:  "value-" + c.name,
			}
		}
		return Decision{Class: Veiled, Spans: whole, Shape: sh, Rule: "value-" + c.name}
	}

	// Rule 4. A public bundle already ships this value.
	//
	// This runs before the name rules, because the prefix is the stronger
	// statement: the developer has said the value reaches the browser. It does
	// not run before the shape rule at rule 3, and it refuses a name that holds
	// a word which is only ever a credential. See neverPublic in name.go.
	if publicPrefixOpens(key) {
		return Decision{Class: Open, Shape: sh, Rule: "public-prefix"}
	}

	// Rule 5. The name. See name.go for how a name is read.
	switch readName(key, value) {
	case nameSecret:
		return Decision{Class: Veiled, Spans: whole, Shape: sh, Rule: "name-secret"}
	case nameConfig:
		return Decision{Class: Open, Shape: sh, Rule: "name-not-secret"}
	}

	// Rule 6. A random looking value with an unusual name.
	if shape.LooksRandom(value) {
		return Decision{Class: Veiled, Spans: whole, Shape: sh, Rule: "entropy"}
	}

	return Decision{Class: Open, Shape: sh, Rule: "default-open"}
}

// composite finds every field of a structured value that must be veiled.
//
// The four forms are cumulative and not mutually exclusive. A gateway URL can
// carry a password in its authority and a token in its query at the same time,
// and an early return kept the token in the clear.
//
// A span that overlaps one already kept is dropped, and the first rule to
// claim a stretch of the value wins it. Every reference is made unique, so two
// forms that both name a password do not write two values under one reference.
func composite(key, value string) ([]handle.Span, string) {
	base := handle.Ref(key)
	used := map[string]bool{}
	var spans []handle.Span
	var rules []string

	// ref returns a reference that no other span of this value holds.
	ref := func(suffix string) string {
		want := base + suffix
		for i := 2; used[want]; i++ {
			want = base + suffix + strconv.Itoa(i)
		}
		used[want] = true
		return want
	}
	// add keeps a span unless it overlaps one already kept.
	add := func(rule string, start, end int, suffix string) {
		for _, s := range spans {
			if start < s.End && s.Start < end {
				return
			}
		}
		spans = append(spans, handle.Span{Start: start, End: end, Ref: ref(suffix)})
		if len(rules) == 0 || rules[len(rules)-1] != rule {
			rules = append(rules, rule)
		}
	}

	if m := urlBasicAuth.FindStringSubmatchIndex(value); m != nil {
		add("url-password", m[4], m[5], "_password")
	}
	if m := adoPassword.FindStringSubmatchIndex(value); m != nil {
		add("connection-string-password", m[4], m[5], "_password")
	}
	if m := bearerToken.FindStringSubmatchIndex(value); m != nil {
		add("bearer-token", m[4], m[5], "_token")
	}
	for _, m := range urlQueryCred.FindAllStringSubmatchIndex(value, -1) {
		add("url-query-credential", m[4], m[5], "_param")
	}
	if len(spans) == 0 {
		return nil, ""
	}
	return spans, strings.Join(rules, "+")
}

// Project renders the value as the agent will see it.
func Project(value string, d Decision) string {
	if d.Class == Open {
		return value
	}
	return handle.Embed(value, d.Spans)
}

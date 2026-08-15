// Package classify decides how much of a value an AI agent may see.
//
// A value is veiled unless a rule opens it. The rules run in a fixed order and
// every decision carries the name of the rule that fired, because the init
// table shows that name to the human. A classifier that cannot explain itself
// does not get trusted, and a tool that is not trusted gets switched off.
package classify

import (
	"regexp"
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
		{regexp.MustCompile(`^gh[pousr]_[A-Za-z0-9]{36,}$`), "github-token", 0},
		{regexp.MustCompile(`^glpat-[A-Za-z0-9_\-]{20,}$`), "gitlab-token", 0},
		{regexp.MustCompile(`^npm_[A-Za-z0-9]{36}$`), "npm-token", 0},
		{regexp.MustCompile(`^xox[bpsara]-[0-9A-Za-z\-]{10,}$`), "slack-token", 0},
		{regexp.MustCompile(`^AIza[0-9A-Za-z_\-]{35}$`), "google-api-key", 0},
		{regexp.MustCompile(`^eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}$`), "jwt", 0},
		{regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`), "private-key", 0},
	}

	// A name that a public bundle already ships. Such a value is not a secret.
	publicPrefix = regexp.MustCompile(`^(NEXT_PUBLIC_|EXPO_PUBLIC_|VITE_|REACT_APP_|PUBLIC_|NUXT_PUBLIC_|GATSBY_)`)

	// A name that describes a number, a duration or a mode. This rule runs
	// before the secret-name rule, so REFRESH_TOKEN_TTL_DAYS stays open.
	neverSecret = regexp.MustCompile(`(?i)(_TTL|TTL_|TIMEOUT|EXPIR|DURATION|INTERVAL|_DELAY|RETRY|RETRIES|` +
		`LIMIT|_MAX|MAX_|_MIN|MIN_|COUNT|_SIZE|SIZE_|_PORT|^PORT$|REGION|LEVEL|_MODE|MODE_|VERSION|` +
		`^NODE_ENV$|^ENV$|_ENV$|DEBUG|LOCALE|TIMEZONE|CURRENCY|^LANG$|THRESHOLD|ENABLED|DISABLED|` +
		`_DAYS|_HOURS|_MINUTES|_SECONDS|_MS$|ROUNDS|ATTEMPTS|WINDOW|PAGE_|PER_PAGE|` +
		// A path names a place, not a secret. The Docker convention
		// DB_PASSWORD_FILE=/run/secrets/db is a path and must stay readable.
		`_PATH|PATH_|_FILE|_DIR|_FOLDER)`)

	// A name that names a secret.
	secretName = regexp.MustCompile(`(?i)(SECRET|PASSWORD|PASSWD|_PWD|PWD_|TOKEN|PRIVATE|CREDENTIAL|` +
		`_SALT|SALT_|SIGNING|API_KEY|APIKEY|ACCESS_KEY|CLIENT_SECRET|_AUTH$|AUTH_KEY|DSN|` +
		`WEBHOOK_URL|_KEY$|KEY_ID|PASSPHRASE|CERT|LICENSE_KEY)`)

	// Composite forms. Each keeps the readable part and veils one field.
	urlBasicAuth = regexp.MustCompile(`^([a-zA-Z][a-zA-Z0-9+.\-]*://[^:/@\s]+:)([^@/\s]+)(@)`)
	urlQueryCred = regexp.MustCompile(`(?i)([?&](?:token|key|api_key|apikey|password|secret|sig|signature|access_token|auth)=)([^&\s#]+)`)
	adoPassword  = regexp.MustCompile(`(?i)((?:^|;)\s*(?:password|pwd)\s*=\s*)([^;]+)`)
	bearerToken  = regexp.MustCompile(`(?i)^(Bearer\s+)(\S+)$`)
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
	for _, s := range d.Spans {
		if s.Start < 0 || s.End > len(value) || s.Start > s.End {
			continue
		}
		if strings.HasPrefix(value[s.Start:s.End], handle.Scheme) {
			continue
		}
		kept = append(kept, s)
	}
	if len(kept) == 0 {
		return Decision{Class: Open, Shape: d.Shape, Rule: "already-veiled"}
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

	// Rule 1. A composite value keeps its readable part.
	if spans, rule := composite(key, value); len(spans) > 0 {
		return Decision{Class: Partial, Spans: spans, Shape: sh, Rule: rule}
	}

	// Rule 2. A credential shape in the value beats every name rule.
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

	// Rule 3. A public bundle already ships this value.
	if publicPrefix.MatchString(key) {
		return Decision{Class: Open, Shape: sh, Rule: "public-prefix"}
	}

	// Rule 4. A number, a duration or a mode. This must beat rule 5.
	if neverSecret.MatchString(key) {
		return Decision{Class: Open, Shape: sh, Rule: "name-not-secret"}
	}

	// Rule 5. The name says secret.
	if secretName.MatchString(key) {
		return Decision{Class: Veiled, Spans: whole, Shape: sh, Rule: "name-secret"}
	}

	// Rule 6. A random looking value with an unusual name.
	if shape.LooksRandom(value) {
		return Decision{Class: Veiled, Spans: whole, Shape: sh, Rule: "entropy"}
	}

	return Decision{Class: Open, Shape: sh, Rule: "default-open"}
}

// composite finds the one field of a structured value that must be veiled.
func composite(key, value string) ([]handle.Span, string) {
	base := handle.Ref(key)

	if m := urlBasicAuth.FindStringSubmatchIndex(value); m != nil {
		return []handle.Span{{Start: m[4], End: m[5], Ref: base + "_password"}}, "url-password"
	}
	if m := adoPassword.FindStringSubmatchIndex(value); m != nil {
		return []handle.Span{{Start: m[4], End: m[5], Ref: base + "_password"}}, "connection-string-password"
	}
	if m := bearerToken.FindStringSubmatchIndex(value); m != nil {
		return []handle.Span{{Start: m[4], End: m[5], Ref: base + "_token"}}, "bearer-token"
	}
	if all := urlQueryCred.FindAllStringSubmatchIndex(value, -1); len(all) > 0 {
		spans := make([]handle.Span, 0, len(all))
		for i, m := range all {
			ref := base + "_param"
			if i > 0 {
				ref = base + "_param" + string(rune('1'+i))
			}
			spans = append(spans, handle.Span{Start: m[4], End: m[5], Ref: ref})
		}
		return spans, "url-query-credential"
	}
	return nil, ""
}

// Project renders the value as the agent will see it.
func Project(value string, d Decision) string {
	if d.Class == Open {
		return value
	}
	return handle.Embed(value, d.Spans)
}

package classify

import (
	"regexp"
	"strings"

	"github.com/ByteFinch-Technologies/secretveil/internal/shape"
)

// The name rules.
//
// When the value gives no evidence, the variable name is all the tool has. The
// first version of these rules matched a word anywhere in the name, so MIN_
// matched inside ADMIN_PASSWORD and COUNT matched inside ACCOUNT_SECRET. A
// name that says config beat a name that says secret, and 39 of 79 real
// credential names came back open.
//
// These rules read the name as words instead. A term matches a whole word, the
// rightmost term that means anything decides, and a two-word term is tried
// before a one-word term.
//
// The two tables are not symmetric, and the asymmetry is the whole design. A
// wrong secret word costs a false veil, and a false veil breaks nothing: the
// real value still reaches the child process, and only the agent stops seeing
// it. A wrong config word costs a credential in plain text. So a config term
// must also agree with the value before it opens anything.

// termKind says what a value must look like before a config term may open it.
// An empty kind puts no requirement on the value.
type termKind string

const (
	kindAny     termKind = ""
	kindNumber  termKind = "number"
	kindPath    termKind = "path"
	kindVersion termKind = "version"
	kindBool    termKind = "boolean"
	kindWord    termKind = "word"
	kindURL     termKind = "url"
	// kindLabel accepts either: a short readable word or a host and path. A
	// JWT issuer is written both ways and neither one is a credential.
	kindLabel termKind = "label"
	kindHash  termKind = "hash"
)

// configTerm is one word that says the value is configuration.
type configTerm struct {
	kind termKind
	// beats says the term opens the value even when a secret word appears
	// elsewhere in the name. It is true only where the value itself proves the
	// term. REFRESH_TOKEN_TTL_DAYS=30 holds the word TOKEN and the value is a
	// number, so it is a number of days and not a token.
	//
	// It is false for a term that describes a credential instead of replacing
	// it. DB_PASSWORD_SECRET_NAME names a password and TOKEN_TYPE describes a
	// token, but neither word proves that this value is not the credential
	// itself. Such a term opens a value only when no secret word appears
	// anywhere in the name.
	beats bool
}

// secretTerms are the words that say a value is a credential. A key of two
// words joined by an underscore is a two-word term.
var secretTerms = wordSet(`
	SECRET PASSWORD PASSWD PWD PASS PASSPHRASE TOKEN PRIVATE CREDENTIAL CRED
	CREDS KEY APIKEY SALT SIGNING SIGNATURE DSN CERT CERTIFICATE AUTH BEARER
	JWT MNEMONIC PHRASE SEED HMAC TOTP PIN NONCE PAT SAS WEBHOOK ENCRYPTION
	CIPHER
	API_KEY ACCESS_KEY SECRET_KEY PRIVATE_KEY SIGNING_KEY AUTH_KEY LICENSE_KEY
	CLIENT_SECRET WEBHOOK_URL KEY_ID SEED_PHRASE RECOVERY_PHRASE SERVICE_ROLE
	CONNECTION_STRING ENCRYPTION_IV
`)

// configTerms are the words that say a value is configuration. See the comment
// on configTerm for what the second column means.
var configTerms = map[string]configTerm{}

func init() {
	add := func(k termKind, beats bool, list string) {
		for w := range wordSet(list) {
			configTerms[w] = configTerm{kind: k, beats: beats}
		}
	}

	// A number proves itself. No credential is a bare number.
	add(kindNumber, true, `
		TTL TIMEOUT DURATION INTERVAL DELAY RETRY RETRIES LIMIT MAX MIN COUNT
		SIZE PORT ROUNDS ATTEMPTS THRESHOLD DAYS HOURS MINUTES SECONDS MS
		WORKERS CONCURRENCY REPLICAS LENGTH DEPTH OFFSET PAGE BACKOFF QUOTA
		WEIGHT PRIORITY EXPIRY EXPIRES EXPIRATION PER_PAGE
	`)
	// A path names a place. The Docker convention DB_PASSWORD_FILE=/run/x is
	// a path and must stay readable.
	add(kindPath, true, `PATH FILE DIR DIRECTORY FOLDER ROOT HOME SOCKET MOUNT`)
	add(kindVersion, true, `VERSION RELEASE TAG`)
	add(kindBool, true, `ENABLED DISABLED ENABLE DISABLE DEBUG VERBOSE STRICT DRY INSECURE`)
	// A short readable word is an enum value, not a credential.
	add(kindWord, true, `
		LEVEL MODE ENV ENVIRONMENT LOCALE TIMEZONE TZ CURRENCY LANG LANGUAGE
		FORMAT REGION ZONE STAGE TIER PROFILE DRIVER ADAPTER ENGINE PROVIDER
		STRATEGY SCHEME PROTOCOL METHOD CHANNEL TOPIC QUEUE BUCKET NAMESPACE
		CLUSTER COLOR THEME PLATFORM ARCH
	`)
	add(kindURL, true, `URL URI ENDPOINT HOST HOSTNAME DOMAIN ORIGIN ADDR ADDRESS SERVER`)
	add(kindAny, true, `PUBLIC PUBLIC_KEY`)
	// These name a part of a credential system and never hold the credential.
	// An algorithm, a header name, a JWT issuer and a cache prefix are all
	// short readable labels, so the value still has to read as one.
	add(kindLabel, true, `ALGORITHM ALGO ISSUER AUDIENCE TYPE PREFIX SUFFIX HEADER HEADER_NAME`)

	// These describe a credential without proving that the value is not one,
	// so a secret word anywhere in the name overrules them.
	add(kindAny, false, `
		NAME ID LABEL TITLE DESCRIPTION SLUG IDENTIFIER USER USERNAME EMAIL
	`)
	// A hash of a credential is not the credential. The value has to be a
	// hash: PASSWORD_HASH=$2b$12$... is a bcrypt digest, not hexadecimal, so
	// this term does not open it.
	add(kindHash, false, `SHA HASH COMMIT REVISION REV DIGEST CHECKSUM ETAG FINGERPRINT`)
}

// nameVerdict is what the name rules concluded.
// neverPublic holds the words that a public prefix can never open.
//
// A bundle prefix such as NEXT_PUBLIC_ says the value ships to the browser.
// For most names that is true and the value is open by design: a Supabase anon
// key and a Sentry DSN are both meant to be read by anyone.
//
// These words are the exception. A developer who writes
// NEXT_PUBLIC_STRIPE_SECRET_KEY has made a mistake, and the tool must not
// repeat it. The list holds only the words that name a credential and nothing
// else. KEY, DSN, ID and AUTH are not here, because each one has a real public
// use.
var neverPublic = wordSet(`
	SECRET PASSWORD PASSWD PWD PASS PASSPHRASE PRIVATE CREDENTIAL CRED CREDS
	TOKEN SIGNING SALT MNEMONIC PHRASE SEED HMAC TOTP PIN PAT SAS ENCRYPTION
	CIPHER SERVICE_ROLE CONNECTION_STRING PRIVATE_KEY SECRET_KEY CLIENT_SECRET
`)

// publicPrefixOpens reports whether a public bundle prefix decides this name.
func publicPrefixOpens(key string) bool {
	if !publicPrefix.MatchString(key) {
		return false
	}
	segs := segments(key)
	for i, s := range segs {
		if neverPublic[singular(s)] {
			return false
		}
		if i > 0 && neverPublic[segs[i-1]+"_"+s] {
			return false
		}
	}
	return true
}

type nameVerdict int

const (
	// nameSilent means no word in the name means anything to either table.
	nameSilent nameVerdict = iota
	nameSecret
	nameConfig
)

// readName applies the name rules to one key and value.
func readName(key, value string) nameVerdict {
	segs := segments(key)

	// A secret word anywhere in the name blocks every term whose beats field
	// is false. Find that first, because the walk below needs to know it.
	anySecret := false
	for i, s := range segs {
		if i > 0 && secretTerms[segs[i-1]+"_"+s] {
			anySecret = true
		}
		if secretTerms[singular(s)] {
			anySecret = true
		}
	}

	// The rightmost term that means anything decides. A term whose value
	// disagrees decides nothing, and the walk carries on to its left.
	sawTerm := false
	for i := len(segs) - 1; i >= 0; i-- {
		if i > 0 {
			if v, ok := readTerm(segs[i-1]+"_"+segs[i], value, anySecret, &sawTerm); ok {
				return v
			}
		}
		if v, ok := readTerm(singular(segs[i]), value, anySecret, &sawTerm); ok {
			return v
		}
	}
	if anySecret {
		return nameSecret
	}
	if sawTerm {
		return nameSilent
	}

	// Nothing in the name is a word this tool knows. Only now is a secret word
	// looked for inside a word, so that MYPASSWORD is still caught. A config
	// word is never looked for this way, because a wrong config word opens a
	// credential.
	upper := strings.ToUpper(key)
	for term := range secretTerms {
		if len(term) >= 4 && !strings.Contains(term, "_") && strings.Contains(upper, term) {
			return nameSecret
		}
	}
	return nameSilent
}

// readTerm reads one term. The second result says whether the term decided.
func readTerm(term, value string, anySecret bool, sawTerm *bool) (nameVerdict, bool) {
	if secretTerms[term] {
		return nameSecret, true
	}
	c, ok := configTerms[term]
	if !ok {
		return nameSilent, false
	}
	*sawTerm = true
	if !valueIs(c.kind, value) {
		return nameSilent, false
	}
	if !c.beats && anySecret {
		return nameSilent, false
	}
	return nameConfig, true
}

// segments splits a variable name into words.
//
// It splits on the usual separators, at a lower or digit followed by an upper,
// and at an upper followed by an upper and a lower, so stripeSecretKey and
// APIKeyId both come apart. A digit never splits a word, so AUTH0 stays one
// word and does not become AUTH.
func segments(key string) []string {
	var out []string
	var b strings.Builder
	flush := func() {
		if b.Len() > 0 {
			out = append(out, strings.ToUpper(b.String()))
			b.Reset()
		}
	}
	r := []rune(key)
	for i, c := range r {
		if strings.ContainsRune("_-./: \t", c) {
			flush()
			continue
		}
		if i > 0 && isUpper(c) {
			prev := r[i-1]
			next := rune(0)
			if i+1 < len(r) {
				next = r[i+1]
			}
			if isLower(prev) || isDigit(prev) || (isUpper(prev) && isLower(next)) {
				flush()
			}
		}
		b.WriteRune(c)
	}
	flush()
	return out
}

func isUpper(c rune) bool { return c >= 'A' && c <= 'Z' }
func isLower(c rune) bool { return c >= 'a' && c <= 'z' }
func isDigit(c rune) bool { return c >= '0' && c <= '9' }

// singular drops a plural S when the singular is a term this tool knows. It
// never invents a word: KEYS becomes KEY, and GLASS stays GLASS.
func singular(w string) string {
	if len(w) > 3 && strings.HasSuffix(w, "S") {
		if s := w[:len(w)-1]; secretTerms[s] {
			return s
		}
	}
	return w
}

// wordSet turns a whitespace separated list into a set.
func wordSet(list string) map[string]bool {
	set := map[string]bool{}
	for _, w := range strings.Fields(list) {
		set[w] = true
	}
	return set
}

// ------------------------------------------------------------- the value

var (
	reNumber  = regexp.MustCompile(`^-?[0-9]+(\.[0-9]+)?\s*[A-Za-z%]{0,3}$`)
	reVersion = regexp.MustCompile(`^[vV]?[0-9]+(\.[0-9]+){0,3}([-+][0-9A-Za-z.\-]+)?$`)
	reHash    = regexp.MustCompile(`^[0-9a-fA-F]{7,64}$`)
	reHost    = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?)+(:[0-9]{1,5})?(/.*)?$`)
	reLabel   = regexp.MustCompile(`^[a-z0-9][a-z0-9\-]{0,62}$`)
	reLowerun = regexp.MustCompile(`[a-z]{3}`)
)

var boolWords = wordSet(`true false yes no on off 1 0 enabled disabled`)

// valueIs reports whether the value agrees with the kind of a config term.
func valueIs(k termKind, value string) bool {
	v := strings.TrimSpace(value)
	if v == "" {
		return true
	}
	switch k {
	case kindAny:
		return true
	case kindNumber:
		return reNumber.MatchString(v)
	case kindBool:
		return boolWords[strings.ToLower(v)]
	case kindVersion:
		return reVersion.MatchString(v)
	case kindHash:
		return reHash.MatchString(v)
	case kindPath:
		return looksLikePath(v)
	case kindURL:
		return looksLikeHost(v)
	case kindWord:
		return looksLikeWord(v)
	case kindLabel:
		return looksLikeWord(v) || looksLikeHost(v)
	}
	return false
}

// looksLikePath wants two or more parts, each short, and a run of lowercase
// letters somewhere. A random token with a slash in it does not qualify.
func looksLikePath(v string) bool {
	if strings.Contains(v, "://") || len(v) > 512 {
		return false
	}
	parts := strings.Split(v, "/")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if len(p) > 64 {
			return false
		}
	}
	return reLowerun.MatchString(v)
}

// looksLikeHost accepts a URL, a host and port, or a single name such as the
// service name of a container. A single name has to read as a word, so that a
// random token under the name HOST is not opened.
func looksLikeHost(v string) bool {
	if strings.Contains(v, "://") {
		return true
	}
	if reHost.MatchString(v) {
		return true
	}
	base, _, _ := strings.Cut(v, ":")
	return reLabel.MatchString(base) && reLowerun.MatchString(base) && !shape.LooksRandom(base)
}

// looksLikeWord accepts a short readable value such as an enum or a locale.
func looksLikeWord(v string) bool {
	if len(v) > 24 || strings.ContainsAny(v, " \t\n\r") {
		return false
	}
	return !shape.LooksRandom(v)
}

// SegmentsForTest exposes the tokeniser to the test of this package. The
// tokeniser decides every name rule, so it is pinned by its own test.
func SegmentsForTest(key string) []string { return segments(key) }

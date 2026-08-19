package classify_test

import (
	"strings"
	"testing"

	"github.com/ByteFinch-Technologies/secretveil/internal/classify"
	"github.com/ByteFinch-Technologies/secretveil/internal/corpus"
)

// TestASecretNameIsVeiled holds the list of real credential variable names
// that the first version of the rules opened.
//
// The value is a weak human password on purpose. No value rule can save it, so
// only the name rule decides, and a miss here is a credential in plain text.
func TestASecretNameIsVeiled(t *testing.T) {
	names := strings.Fields(`
		ADMIN_PASSWORD KEYCLOAK_ADMIN_PASSWORD GRAFANA_ADMIN_PASSWORD
		WINDOWS_PASSWORD MAX_PASSWORD MIN_PASSWORD DB_PASSWORD MYSQL_PASSWORD
		POSTGRES_PASSWORD REDIS_PASSWORD SMTP_PASSWORD
		SMTP_PASS DB_PASS MYSQL_PASS POSTGRES_PASS FTP_PASS USER_PASS
		GCP_SERVICE_ACCOUNT_KEY AZURE_STORAGE_ACCOUNT_KEY ALGOLIA_ADMIN_KEY
		ACCOUNT_SECRET_KEY MINIO_SECRET_KEY COUNTRY_API_KEY AWS_SECRET_ACCESS_KEY
		COUNT_TOKEN WINDOW_TOKEN DEBUG_TOKEN VERSION_SECRET REGION_SECRET
		MODE_SECRET SIZE_TOKEN LIMIT_TOKEN PORT_SECRET
		DB_CREDS WALLET_MNEMONIC SEED_PHRASE RECOVERY_PHRASE HMAC_KEY TOTP_SEED
		ENCRYPTION_IV GITHUB_PAT AZURE_SAS SUPABASE_SERVICE_ROLE
		DATABASE_CONNECTION_STRING SLACK_WEBHOOK SENTRY_DSN JWT_SIGNING_KEY
		stripeSecretKey databasePassword github-token smtp.password
		MYPASSWORD apiKeySecret NEXT_PUBLIC_STRIPE_SECRET_KEY
	`)
	for _, name := range names {
		if d := classify.Classify(name, "Hunter2!"); d.Class == classify.Open {
			t.Errorf("%s is open with rule %q and it names a credential", name, d.Rule)
		}
	}
}

// TestAConfigNameStaysOpen is the other side of the same coin. A false veil
// breaks nothing, but a tool that veils the port number is a tool that gets
// switched off.
func TestAConfigNameStaysOpen(t *testing.T) {
	cases := []struct{ key, value string }{
		{"PORT", "3000"},
		{"NODE_ENV", "production"},
		{"LOG_LEVEL", "debug"},
		{"AWS_REGION", "us-east-1"},
		{"MAX_RETRIES", "5"},
		{"CACHE_TTL", "300"},
		{"NEXT_PUBLIC_SITE_URL", "https://example.com"},
		{"REFRESH_TOKEN_TTL_DAYS", "30"},
		{"SESSION_TIMEOUT_SECONDS", "1800"},
		{"PASSWORD_MIN_LENGTH", "12"},
		{"BCRYPT_ROUNDS", "12"},
		{"DB_PASSWORD_FILE", "/run/secrets/db_password"},
		{"TLS_CERT_PATH", "/etc/ssl/certs/server.pem"},
		{"APP_VERSION", "1.4.2"},
		{"DEBUG", "true"},
		{"FEATURE_X_ENABLED", "false"},
		{"DB_HOST", "postgres"},
		{"DATABASE_HOST", "db.internal"},
		{"FIREBASE_AUTH_DOMAIN", "myapp.firebaseapp.com"},
		{"JWT_ALGORITHM", "HS256"},
		{"JWT_ISSUER", "https://auth.example.com"},
		{"JWT_AUDIENCE", "mobile-app"},
		{"TOKEN_TYPE", "Bearer"},
		{"AUTH_HEADER_NAME", "Authorization"},
		{"CACHE_KEY_PREFIX", "prod:v2"},
		{"GIT_COMMIT_SHA", "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"},
		{"PASSWORD_HASH_ALGO", "bcrypt"},
		{"CLIENT_ID", "acme-web"},
		{"DB_USER", "postgres"},
		{"AUTH0_DOMAIN", "dev-abc.eu.auth0.com"},
		{"SENTRY_DSN_PUBLIC", "https://o1.ingest.example.com/2"},
		{"PER_PAGE", "50"},
		{"TIMEZONE", "Europe/Berlin"},
		{"CURRENCY", "AED"},
	}
	for _, c := range cases {
		if d := classify.Classify(c.key, c.value); d.Class != classify.Open {
			t.Errorf("%s=%s is %s with rule %q and it is configuration", c.key, c.value, d.Class, d.Rule)
		}
	}
}

// TestAConfigWordDoesNotOpenACredential proves the value has to agree with the
// word. Each key below holds a word that usually means configuration, and each
// value is a credential and not what the word describes.
func TestAConfigWordDoesNotOpenACredential(t *testing.T) {
	cases := []struct{ key, value string }{
		{"DB_PASSWORD_FILE", "letmein"},
		{"PASSWORD_HASH", "$2b$12$K3JNiBhAZ0pT7uOaZ1s2ReQ"},
		{"SECRET_MODE", "9f8e7d6c5b4a39281706f5e4d3c2b1a0"},
		{"TOKEN_PREFIX", "ghp_016f2c8d4e9a7b3c5d1e8f0a2b4c6d8e0f2a"},
		{"API_KEY_REGION", "kR7fMz2QwXpLn4Vb8TyH3sJd6Ga1Ce9U"},
		{"CLIENT_SECRET_TYPE", "s3cr3tV4lu3W1thN0Sp4c3sAtAll"},
		{"AUTH_TOKEN_VERSION", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcde"},
	}
	for _, c := range cases {
		if d := classify.Classify(c.key, c.value); d.Class == classify.Open {
			t.Errorf("%s=%s is open with rule %q and the value is not what the name describes", c.key, c.value, d.Rule)
		}
	}
}

// TestSegmentsReadsAName pins the tokeniser. A digit must never split a word,
// or AUTH0_DOMAIN would be read as a name that says AUTH.
func TestSegmentsReadsAName(t *testing.T) {
	cases := []struct {
		key  string
		want string
	}{
		{"DB_PASSWORD", "DB PASSWORD"},
		{"stripeSecretKey", "STRIPE SECRET KEY"},
		{"github-token", "GITHUB TOKEN"},
		{"smtp.password", "SMTP PASSWORD"},
		{"AUTH0_DOMAIN", "AUTH0 DOMAIN"},
		{"APIKeyId", "API KEY ID"},
		{"NEXT_PUBLIC_SITE_URL", "NEXT PUBLIC SITE URL"},
		{"OAuth2Token", "O AUTH2 TOKEN"},
		{"PORT", "PORT"},
	}
	for _, c := range cases {
		if got := strings.Join(classify.SegmentsForTest(c.key), " "); got != c.want {
			t.Errorf("segments(%q) = %q and the rules need %q", c.key, got, c.want)
		}
	}
}

// TestAVariableReferenceNeverEntersTheStore holds the rule that a value which
// points at another variable is not itself a secret. Veiling one of these
// wrote the literal text of the reference into the encrypted store.
func TestAVariableReferenceNeverEntersTheStore(t *testing.T) {
	cases := []struct{ key, value string }{
		{"DB_PASSWORD", "${SECRET_ROOT_PW}"},
		{"API_KEY", "$OTHER_KEY"},
		{"STRIPE_SECRET_KEY", "${STRIPE_KEY}"},
		{"AUTH_TOKEN", "  ${TOKEN_SOURCE}  "},
	}
	for _, c := range cases {
		d := classify.Classify(c.key, c.value)
		if d.Class != classify.Open || d.Rule != "variable-reference" {
			t.Errorf("%s=%s is %s by rule %q and it only names another variable",
				c.key, c.value, d.Class, d.Rule)
		}
	}
	// A reference inside a larger value loses its span and keeps the rest.
	d := classify.Classify("DATABASE_URL", "postgres://app:${DB_PW}@db.internal:5432/app")
	if d.Rule != "variable-reference" {
		t.Errorf("a URL whose only credential is a reference is %q and must be variable-reference", d.Rule)
	}
	// A real password in the same position still goes to the store.
	d = classify.Classify("DATABASE_URL", "postgres://app:tr0ub4dor@db.internal:5432/app")
	if d.Class != classify.Partial {
		t.Errorf("a URL with a real password is %s and must stay partial", d.Class)
	}
}

// TestEveryCompositeFieldIsVeiled proves the four composite forms are
// cumulative. A URL that carries a password and a token lost the token.
func TestEveryCompositeFieldIsVeiled(t *testing.T) {
	cases := []struct {
		key, value string
		mustHide   []string
	}{
		{
			"GATEWAY_URL",
			"https://svcuser:D9Bth4l4aEAaxt@gateway.example.com/v1?token=s3cr3tvalue123&key=aBcDeFgHiJkL",
			[]string{"D9Bth4l4aEAaxt", "s3cr3tvalue123", "aBcDeFgHiJkL"},
		},
		{
			"CALLBACK",
			"https://api.example.com/hook?api_key=kR7fMz2QwXpLn4Vb&signature=0f1e2d3c4b5a6978",
			[]string{"kR7fMz2QwXpLn4Vb", "0f1e2d3c4b5a6978"},
		},
	}
	for _, c := range cases {
		d := classify.Classify(c.key, c.value)
		seen := classify.Project(c.value, d)
		for _, part := range c.mustHide {
			if strings.Contains(seen, part) {
				t.Errorf("%s: the agent still reads %q in %q (rule %q)", c.key, part, seen, d.Rule)
			}
		}
		refs := map[string]bool{}
		for _, s := range d.Spans {
			if refs[s.Ref] {
				t.Errorf("%s: two spans share the reference %q, so one value would overwrite the other", c.key, s.Ref)
			}
			refs[s.Ref] = true
		}
	}
}

// TestEveryVendorShapeIsRecognised gives each shape a bland name, so only the
// value rule can save it.
//
// The values come from the corpus generator and are not written here. A file
// of credential-shaped literals is wrong in a public repository: the host
// refuses the push, and a reader cannot tell a made-up key from a real one.
// The same lesson removed the corpus file itself in PR 0.
//
// The rule name is checked as well as the class. A shape that the entropy rule
// happens to catch is not recognised, it is only lucky, and the next value of
// that vendor may be short enough to slip through.
func TestEveryVendorShapeIsRecognised(t *testing.T) {
	// The note the corpus writes for a vendor row. The shape name follows it.
	const prefix = "the value carries the "
	const suffix = " shape"

	seen := map[string]bool{}
	for _, r := range corpus.Generate() {
		if !strings.HasPrefix(r.Note, prefix) || !strings.HasSuffix(r.Note, suffix) {
			continue
		}
		name := strings.TrimSuffix(strings.TrimPrefix(r.Note, prefix), suffix)
		seen[name] = true

		d := classify.Classify(r.Key, r.Value)
		if d.Class == classify.Open {
			t.Errorf("a %s value under the name %s is open by rule %q", name, r.Key, d.Rule)
			continue
		}
		if !strings.HasPrefix(d.Rule, "value-") {
			t.Errorf("a %s value under the name %s was caught by rule %q and not by a shape rule",
				name, r.Key, d.Rule)
		}
	}

	// The loop above proves only what the corpus holds. This list is the
	// contract: a shape named here must keep a row, so that deleting the row
	// and deleting the rule cannot happen quietly together.
	for _, name := range strings.Fields(`
		aws-access-key-id aws-temp-key-id openai-key openai-project-key
		stripe-live-key stripe-test-key stripe-restricted-key github-classic
		github-oauth github-user github-server github-refresh gitlab-token
		npm-token npm-token-long slack-bot slack-user google-api-key jwt
		sendgrid twilio-signing-key square-token rsa-private-key
		openssh-private-key ec-private-key pgp-private-key
	`) {
		if !seen[name] {
			t.Errorf("the corpus holds no %s row, so nothing measures that shape", name)
		}
	}
}

package classify_test

import (
	"strings"
	"testing"

	"github.com/ByteFinch-Technologies/secretveil/internal/classify"
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

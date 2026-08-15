package classify

import (
	"strings"
	"testing"
)

// The labelled corpus. Every value here is synthetic. No real credential is in
// this repository.
//
// The gate is one-sided: a labelled secret must never come back Open. That is
// the direction that leaks. A labelled non-secret that comes back veiled is a
// nuisance, and it is measured but not fatal.

type sample struct {
	key   string
	value string
	// want is the required class. For a secret, Open is always a failure.
	want Class
}

var secrets = []sample{
	{"JWT_SECRET", "3f8a1c9e2b7d4f6a0c5e8b1d3a7f9c2e4b6d8a0f", Veiled},
	{"JWT_TOKEN_SECRET", "d41d8cd98f00b204e9800998ecf8427e", Veiled},
	{"SESSION_SECRET", "kQ8vN2xR7mL4pT9wY3zA6bC1dE5fG0hJ", Veiled},
	{"NEXTAUTH_SECRET", "aBcDeF1234567890aBcDeF1234567890", Veiled},
	{"AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", Veiled},
	{"AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE", Partial},
	{"STRIPE_SECRET_KEY", "sk_live_51HxYzAbCdEfGhIjKlMnOpQrSt", Veiled},
	{"OPENAI_API_KEY", "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789", Veiled},
	{"GITHUB_TOKEN", "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789", Veiled},
	{"GITLAB_TOKEN", "glpat-AbCdEfGhIjKlMnOpQr", Veiled},
	{"SLACK_BOT_TOKEN", "xoxb-1234567890-abcdefghijklmnop", Veiled},
	{"FIREBASE_API_KEY", "AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q", Veiled},
	{"SMTP_PASSWORD", "hunter2hunter2hunter2", Veiled},
	{"DB_PASSWORD", "s3cr3tp4ss", Veiled},
	{"TWILIO_AUTH_TOKEN", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", Veiled},
	{"ENCRYPTION_KEY", "0123456789abcdef0123456789abcdef", Veiled},
	{"SIGNING_KEY", "MHcCAQEEIBxyzabc0123456789defghij", Veiled},
	{"CLIENT_SECRET", "GOCSPX-AbCdEfGhIjKlMnOpQrStUvWx", Veiled},
	{"SENTRY_AUTH_TOKEN", "0123456789abcdef0123456789abcdef0123456789abcdef", Veiled},
	{"PRIVATE_KEY", "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----", Veiled},
	{"API_SECRET", "abc123def456ghi789jkl012", Veiled},
	{"LICENSE_KEY", "XXXX-YYYY-ZZZZ-WWWW-VVVV", Veiled},
	{"WEBHOOK_URL", "https://hooks.example.com/services/T00/B00/XyZ123", Veiled},
	{"MASTER_PASSPHRASE", "correct horse battery staple", Veiled},

	// A secret with an unusual name. Only the entropy rule can catch these.
	{"FOO_BLOB", "8Kz2mQ9pR4tW7yA1cD6fH0jL3nP5sV8x", Veiled},
	{"INTERNAL_HANDSHAKE", "b7d29f4e1a6c8035be92d1f7a4c60e8d", Veiled},

	// Composite values. The readable part survives, the credential does not.
	{"DATABASE_URL", "postgresql://app:tr0ub4dor@db.internal:5432/payroll", Partial},
	{"MONGO_URI", "mongodb+srv://svc:P%40ssw0rd@cluster0.mongodb.net/prod", Partial},
	{"REDIS_URL", "redis://default:abc123xyz@redis.internal:6379", Partial},
	{"AMQP_URL", "amqp://guest:guestpass@rabbit:5672/", Partial},
	{"CONNECTION_STRING", "Server=db;Database=app;User Id=sa;Password=Str0ng!Pass;", Partial},
	{"AUTHORIZATION_HEADER", "Bearer abc123def456ghi789jkl012mno345", Partial},
	{"CALLBACK_ENDPOINT", "https://api.example.com/hook?token=s3cr3tvalue123", Partial},
}

var nonSecrets = []sample{
	{"NODE_ENV", "production", Open},
	{"PORT", "3000", Open},
	{"HOST", "0.0.0.0", Open},
	{"AWS_REGION", "me-south-1", Open},
	{"LOG_LEVEL", "debug", Open},
	{"TZ", "Asia/Karachi", Open},
	{"DEBUG", "false", Open},
	{"API_URL", "https://api.example.com/v1", Open},
	{"CORS_ORIGIN", "https://app.example.com", Open},
	{"DATABASE_URL", "postgresql://localhost:5432/payroll", Open},
	{"REDIS_URL", "redis://127.0.0.1:6379", Open},
	{"SMTP_HOST", "smtp.gmail.com", Open},
	{"SMTP_PORT", "587", Open},
	{"MAX_UPLOAD_SIZE", "10485760", Open},
	{"BCRYPT_ROUNDS", "10", Open},
	{"RATE_LIMIT_WINDOW", "900000", Open},

	// These three are the false alarms that an earlier audit produced. Each
	// name contains a secret word but names a number.
	{"REFRESH_TOKEN_TTL_DAYS", "30", Open},
	{"AUTH_RATE_LIMIT_MAX", "5", Open},
	{"SIGNUP_TOKEN_TTL", "3600", Open},

	// A path names a place, not a secret.
	{"PRIVATE_KEY_PATH", "/etc/ssl/private/server.pem", Open},
	{"DB_PASSWORD_FILE", "/run/secrets/db_password", Open},

	// A public bundle already ships these.
	{"NEXT_PUBLIC_API_URL", "https://api.example.com", Open},
	{"NEXT_PUBLIC_SUPABASE_ANON_KEY", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", Open},
	{"VITE_APP_NAME", "Payroll", Open},
	{"EXPO_PUBLIC_SENTRY_DSN", "https://abc@o123.ingest.sentry.io/456", Open},
	{"REACT_APP_VERSION", "1.4.2", Open},
}

func TestNoLabelledSecretIsOpen(t *testing.T) {
	for _, s := range secrets {
		d := Classify(s.key, s.value)
		if d.Class == Open {
			t.Errorf("FALSE OPEN: %s classified open by rule %q", s.key, d.Rule)
			continue
		}
		if d.Class != s.want {
			t.Errorf("%s: want %v, got %v (rule %q)", s.key, s.want, d.Class, d.Rule)
		}
	}
}

func TestNonSecretsStayOpen(t *testing.T) {
	veiled := 0
	for _, s := range nonSecrets {
		d := Classify(s.key, s.value)
		if d.Class != Open {
			veiled++
			t.Errorf("false veil: %s=%q became %v by rule %q", s.key, s.value, d.Class, d.Rule)
		}
	}
	rate := float64(veiled) / float64(len(nonSecrets)) * 100
	t.Logf("false-veil rate: %.1f%% (%d of %d)", rate, veiled, len(nonSecrets))
}

// TestProjectionHidesTheSecret is the property that matters most: after
// projection, no part of the secret may remain in the text.
func TestProjectionHidesTheSecret(t *testing.T) {
	cases := []struct {
		key, value, mustNotContain string
	}{
		{"DATABASE_URL", "postgresql://app:tr0ub4dor@db.internal:5432/payroll", "tr0ub4dor"},
		{"REDIS_URL", "redis://default:abc123xyz@redis.internal:6379", "abc123xyz"},
		{"CONNECTION_STRING", "Server=db;Password=Str0ng!Pass;", "Str0ng!Pass"},
		{"AUTHORIZATION_HEADER", "Bearer abc123def456ghi789jkl012mno345", "abc123def456"},
		{"CALLBACK_ENDPOINT", "https://api.example.com/hook?token=s3cr3tvalue123", "s3cr3tvalue123"},
		{"JWT_SECRET", "3f8a1c9e2b7d4f6a0c5e8b1d3a7f9c2e", "3f8a1c9e"},
		{"AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE", "IOSFODNN7EXAMPLE"},
	}
	for _, c := range cases {
		out := Project(c.value, Classify(c.key, c.value))
		if strings.Contains(out, c.mustNotContain) {
			t.Errorf("%s: projection still holds the secret: %q", c.key, out)
		}
		if !strings.Contains(out, "sv://") {
			t.Errorf("%s: projection has no handle: %q", c.key, out)
		}
	}
}

// TestCompositeKeepsTheReadablePart proves the feature that makes the tool
// usable: the agent can still debug a connection fault.
func TestCompositeKeepsTheReadablePart(t *testing.T) {
	value := "postgresql://app:tr0ub4dor@db.internal:5432/payroll"
	out := Project(value, Classify("DATABASE_URL", value))
	for _, keep := range []string{"postgresql://", "app", "db.internal", "5432", "payroll"} {
		if !strings.Contains(out, keep) {
			t.Errorf("projection lost %q: %s", keep, out)
		}
	}
	if out != "postgresql://app:sv://database_url_password@db.internal:5432/payroll" {
		t.Errorf("unexpected projection: %s", out)
	}
}

func TestOpenValueIsUnchanged(t *testing.T) {
	for _, s := range nonSecrets {
		if out := Project(s.value, Classify(s.key, s.value)); out != s.value {
			t.Errorf("%s: an open value was changed to %q", s.key, out)
		}
	}
}

func TestEveryDecisionNamesItsRule(t *testing.T) {
	all := append(append([]sample{}, secrets...), nonSecrets...)
	for _, s := range all {
		if d := Classify(s.key, s.value); d.Rule == "" {
			t.Errorf("%s: decision has no rule name", s.key)
		}
	}
}

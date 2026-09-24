package fixture_test

import (
	"strings"
	"testing"

	"github.com/ByteFinch-Technologies/secretveil/internal/classify"
	"github.com/ByteFinch-Technologies/secretveil/internal/fixture"
)

func TestEachRoleHasItsOwnValue(t *testing.T) {
	a, b := fixture.Value(t, "stored"), fixture.Value(t, "other")
	if a == b {
		t.Fatalf("two roles gave one value: %s", a)
	}
	if a != fixture.Value(t, "stored") {
		t.Fatal("one role gave two values in one test")
	}
	if len(a) != 24 || len(fixture.Long(t, "stored")) != 48 {
		t.Fatalf("the lengths are wrong: %d and %d", len(a), len(fixture.Long(t, "stored")))
	}
}

func TestEachTestHasItsOwnValue(t *testing.T) {
	mine := fixture.Value(t, "stored")
	if other := valueOf(t, "TestSomeOtherTest"); other == mine {
		t.Errorf("two tests share the value %s", mine)
	}
	t.Run("a subtest", func(t *testing.T) {
		if got := fixture.Value(t, "stored"); got != mine {
			t.Errorf("a subtest got %s, and its parent got %s", got, mine)
		}
	})
}

// valueOf gives the value that a test with another name gets.
func valueOf(t *testing.T, name string) string {
	return fixture.Value(named{T: t, name: name}, "stored")
}

type named struct {
	*testing.T
	name string
}

func (n named) Name() string { return n.name }

// TestAFixtureIsASecretAndNoVendorShape proves what every other test relies
// on. The classifier must veil the value, and no vendor rule may read it, or
// the hygiene test would report it.
func TestAFixtureIsASecretAndNoVendorShape(t *testing.T) {
	for _, v := range []string{fixture.Value(t, "stored"), fixture.Long(t, "stored")} {
		for _, key := range []string{"API_KEY", "X"} {
			d := classify.Classify(key, v)
			if d.Class != classify.Veiled {
				t.Errorf("%s=%s is not veiled: %+v", key, v, d)
			}
			if strings.HasPrefix(d.Rule, "value-") {
				t.Errorf("%s=%s matches the vendor rule %s", key, v, d.Rule)
			}
		}
	}
}

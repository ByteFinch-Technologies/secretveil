package migrate

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ByteFinch-Technologies/secretveil/internal/fixture"
)

// TestARenamedReferenceNamesTheEnvironment guards the fault this test file was
// written for.
//
// Three files held API_KEY with three different values. The names that came
// back were api_key, env_api_key and env_api_key_2, because the file name was
// cut at the last dot and ".env.local" and ".env.development" both became
// "env". A developer who read that list could not tell which name held which
// value, which is the one thing the name is for.
func TestARenamedReferenceNamesTheEnvironment(t *testing.T) {
	root := project(t, map[string]string{
		".env":             "API_KEY=" + fixture.Value(t, "stored") + "\n",
		".env.development": "API_KEY=" + fixture.Value(t, "development") + "\n",
		".env.local":       "API_KEY=" + fixture.Value(t, "local") + "\n",
	})
	res, err := Apply(context.Background(), newFakeStore(), Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Renamed) != 2 {
		t.Fatalf("want two renames, got %v", res.Renamed)
	}

	got := map[string]string{}
	for _, r := range res.Renamed {
		got[r.To] = r.File
		if strings.HasSuffix(r.To, "_2") {
			t.Fatalf("the name %q needed a number, so the file name says nothing", r.To)
		}
	}
	for want, file := range map[string]string{
		"env_development_api_key": ".env.development",
		"env_local_api_key":       ".env.local",
	} {
		if got[want] != file {
			t.Fatalf("want the name %q from %s, got %v", want, file, res.Renamed)
		}
	}
}

// TestEachFileHoldsItsOwnHandle proves the rename reached the files as well as
// the store. A name that is right in the report and wrong on disk is worse than
// no rename at all.
func TestEachFileHoldsItsOwnHandle(t *testing.T) {
	root := project(t, map[string]string{
		".env":             "API_KEY=" + fixture.Value(t, "stored") + "\n",
		".env.development": "API_KEY=" + fixture.Value(t, "development") + "\n",
	})
	st := newFakeStore()
	if _, err := Apply(context.Background(), st, Options{Root: root}); err != nil {
		t.Fatal(err)
	}

	dev := read(t, filepath.Join(root, ".env.development"))
	if !strings.Contains(dev, "sv://env_development_api_key") {
		t.Fatalf(".env.development holds the wrong handle:\n%s", dev)
	}
	if st.values["env_development_api_key"] != fixture.Value(t, "development") {
		t.Fatalf("the store holds the wrong value: %v", st.values)
	}
}

// TestASubdirectoryStaysInTheName keeps a monorepo readable. Two apps with the
// same file name need the directory to tell them apart.
func TestASubdirectoryStaysInTheName(t *testing.T) {
	root := project(t, map[string]string{
		".env":          "API_KEY=" + fixture.Value(t, "stored") + "\n",
		"apps/web/.env": "API_KEY=" + fixture.Value(t, "web") + "\n",
	})
	res, err := Apply(context.Background(), newFakeStore(), Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res.Renamed {
		if r.To != "apps_web_env_api_key" {
			t.Fatalf("want apps_web_env_api_key, got %q", r.To)
		}
	}
}

// TestFileTag covers the two kinds directly, including the .npmrc at the top of
// a project. That one has no directory to name, and a rename that produced an
// empty tag would fall back to a number.
func TestFileTag(t *testing.T) {
	cases := []struct {
		kind FileKind
		rel  string
		want string
	}{
		{KindDotenv, ".env", "env"},
		{KindDotenv, ".env.local", "env_local"},
		{KindDotenv, ".env.development", "env_development"},
		{KindDotenv, "apps/web/.env.local", "apps_web_env_local"},
		{KindNpmrc, ".npmrc", "root"},
		{KindNpmrc, "packages/api/.npmrc", "packages_api"},
	}
	for _, c := range cases {
		if got := fileTag(c.kind, c.rel); got != c.want {
			t.Errorf("fileTag(%s, %q) = %q, want %q", c.kind, c.rel, got, c.want)
		}
	}
}

// TestASecondInitNeverReplacesAStoredValue covers the second route to issue
// 56. The store already holds db_pass. A new file with a different DB_PASS
// must get a new name, and the stored value must stay, because every handle
// that names db_pass would otherwise give the new value.
func TestASecondInitNeverReplacesAStoredValue(t *testing.T) {
	root := project(t, map[string]string{
		".env.local": "DB_PASS=fake-second-Hq7Wd2Kx9Lp4\n",
	})
	st := newFakeStore()
	st.values["db_pass"] = "fake-first-Tz3Nc8Rv5Mb1"

	res, err := Apply(context.Background(), st, Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if st.values["db_pass"] != "fake-first-Tz3Nc8Rv5Mb1" {
		t.Fatalf("init replaced the stored value of db_pass: %v", st.values)
	}
	if st.values["env_local_db_pass"] != "fake-second-Hq7Wd2Kx9Lp4" {
		t.Fatalf("the new value is not under a new name: %v", st.values)
	}
	if len(res.Renamed) != 1 || res.Renamed[0].To != "env_local_db_pass" {
		t.Fatalf("want one rename to env_local_db_pass, got %v", res.Renamed)
	}
	if got := read(t, filepath.Join(root, ".env.local")); !strings.Contains(got, "sv://env_local_db_pass") {
		t.Fatalf(".env.local holds the wrong handle:\n%s", got)
	}
}

// TestASecondInitKeepsTheNameOfTheSameValue keeps a second init quiet when
// nothing changed. The same value under the same name is one secret, not two.
func TestASecondInitKeepsTheNameOfTheSameValue(t *testing.T) {
	root := project(t, map[string]string{
		".env.local": "DB_PASS=fake-same-Gy6Bf4Js2Wn8\n",
	})
	st := newFakeStore()
	st.values["db_pass"] = "fake-same-Gy6Bf4Js2Wn8"

	res, err := Apply(context.Background(), st, Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Renamed) != 0 {
		t.Fatalf("the same value got a new name: %v", res.Renamed)
	}
	if got := read(t, filepath.Join(root, ".env.local")); !strings.Contains(got, "sv://db_pass") {
		t.Fatalf(".env.local holds the wrong handle:\n%s", got)
	}
}

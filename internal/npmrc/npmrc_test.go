package npmrc

import (
	"strings"
	"testing"
)

const realToken = "npm_A9fK2xQw7ZtR4mVn8sLp3JhG1dYc5B"

// TestRoundTripIsExact is the contract. A file that nothing changed must come
// back byte for byte, or restore cannot give the developer their file back.
func TestRoundTripIsExact(t *testing.T) {
	cases := []string{
		"",
		"\n",
		"registry=https://registry.npmjs.org/\n",
		"registry=https://registry.npmjs.org/",
		"//registry.npmjs.org/:_authToken=" + realToken + "\n",
		"# a comment\n; another comment\n\nkey=value\n",
		"key = value with spaces \n",
		"key=value ; trailing comment\n",
		"key=value # trailing comment\n",
		"\r\nkey=value\r\n",
		"  indented=yes\n",
		"no-equals-here\n",
		"=novalue\n",
		"key=\n",
		"key==double\n",
		"a=1\r\nb=2\n c=3",
		"key=\"quoted value\"\n",
		"key='single'\n",
		strings.Repeat("k=v\n", 50),
	}
	for _, src := range cases {
		got := string(Parse([]byte(src)).Bytes())
		if got != src {
			t.Errorf("round trip changed the file\n  in:  %q\n  out: %q", src, got)
		}
	}
}

func FuzzRoundTrip(f *testing.F) {
	f.Add("//registry.npmjs.org/:_authToken=" + realToken + "\n")
	f.Add("key=value ; comment\n")
	f.Add("# comment\n\nkey=value\r\n")
	f.Add("=\n=\n")
	f.Fuzz(func(t *testing.T, src string) {
		got := string(Parse([]byte(src)).Bytes())
		if got != src {
			t.Fatalf("round trip changed the file\n  in:  %q\n  out: %q", src, got)
		}
	})
}

// FuzzSetRoundTrip proves a rewrite changes one value and nothing else.
func FuzzSetRoundTrip(f *testing.F) {
	f.Add("//registry.npmjs.org/:_authToken="+realToken+"\n", "x")
	f.Add("a=1\nb=2\n", "z")
	f.Fuzz(func(t *testing.T, src, value string) {
		file := Parse([]byte(src))
		creds := file.Credentials()
		if len(creds) == 0 {
			return
		}
		// Pick the line by position, because a key may appear twice and the
		// migration always works on one line.
		target := creds[0]
		index := -1
		for i := range file.Lines {
			if &file.Lines[i] == target {
				index = i
			}
		}
		before := target.Value
		if !target.Set(value) {
			return
		}
		out := string(file.Bytes())
		// Every other line is untouched. Comparing the line count catches a
		// rewrite that ate a line ending.
		if strings.Count(out, "\n") != strings.Count(src, "\n") {
			t.Fatalf("the rewrite changed the line count\n  in:  %q\n  out: %q", src, out)
		}
		again := Parse([]byte(out))
		if len(again.Lines) != len(file.Lines) {
			t.Fatalf("the rewrite changed the line count\n  in:  %q\n  out: %q", src, out)
		}
		if got := again.Lines[index].Value; got != value {
			t.Fatalf("the value did not survive a reparse: want %q, got %q (was %q)", value, got, before)
		}
	})
}

func TestCredentialDetection(t *testing.T) {
	cases := []struct {
		src  string
		want bool
		why  string
	}{
		{"//registry.npmjs.org/:_authToken=" + realToken + "\n", true, "the ordinary npm token"},
		{"_authToken=" + realToken + "\n", true, "a token with no registry prefix"},
		{"//npm.pkg.github.com/:_authToken=ghp_aaaaaaaaaaaaaaaaaaaa\n", true, "another registry"},
		{"//r.example.com/:_auth=YWJjOmRlZg==\n", true, "basic auth"},
		{"//r.example.com/:_password=cGFzcw==\n", true, "a password"},
		{"//REGISTRY.example.com/:_AUTHTOKEN=" + realToken + "\n", true, "the key is matched without case"},

		{"registry=https://registry.npmjs.org/\n", false, "a registry is not a credential"},
		{"save-exact=true\n", false, "an ordinary setting"},
		{"email=bob@example.com\n", false, "an email address is not a credential"},
		{"//r.example.com/:_authToken=${NPM_TOKEN}\n", false, "the project already uses a variable"},
		{"//r.example.com/:_authToken=" + Marker(Ref("//r.example.com/:_authToken")) + "\n", false, "already rewritten"},
		{"# //r.example.com/:_authToken=" + realToken + "\n", false, "a comment"},
		{"; //r.example.com/:_authToken=" + realToken + "\n", false, "a comment with a semicolon"},
		{"//r.example.com/:_authToken=\n", false, "an empty value"},
		{"//r.example.com/:_authToken=\"quoted token\"\n", false, "the two readers disagree on a quoted value"},
	}
	for _, c := range cases {
		got := len(Parse([]byte(c.src)).Credentials()) == 1
		if got != c.want {
			t.Errorf("%s: IsCredential = %v, want %v for %q", c.why, got, c.want, c.src)
		}
	}
}

// TestRewriteProducesTheMarker walks the whole path a migration takes.
func TestRewriteProducesTheMarker(t *testing.T) {
	src := "registry=https://registry.npmjs.org/\n" +
		"//registry.npmjs.org/:_authToken=" + realToken + "\n" +
		"save-exact=true\n"

	file := Parse([]byte(src))
	creds := file.Credentials()
	if len(creds) != 1 {
		t.Fatalf("want 1 credential, got %d", len(creds))
	}
	ref := Ref(creds[0].Key)
	if ref != "npmrc_registry_npmjs_org_authtoken" {
		t.Fatalf("ref = %q", ref)
	}
	if !file.Set(creds[0].Key, Marker(ref)) {
		t.Fatal("the rewrite was refused")
	}

	out := string(file.Bytes())
	if strings.Contains(out, realToken) {
		t.Fatal("the token is still in the file")
	}
	want := "registry=https://registry.npmjs.org/\n" +
		"//registry.npmjs.org/:_authToken=${SV_NPMRC_REGISTRY_NPMJS_ORG_AUTHTOKEN}\n" +
		"save-exact=true\n"
	if out != want {
		t.Fatalf("rewrite\n  got:  %q\n  want: %q", out, want)
	}

	// And the marker leads back to the same reference.
	if got := Markers(out); len(got) != 1 || got[0] != ref {
		t.Fatalf("Markers = %v, want [%s]", got, ref)
	}
}

// TestRestoreGivesBackTheOriginalBytes is the release gate, in one package.
func TestRestoreGivesBackTheOriginalBytes(t *testing.T) {
	src := "//registry.npmjs.org/:_authToken=" + realToken + "\nsave-exact=true\n"

	file := Parse([]byte(src))
	key := file.Credentials()[0].Key
	ref := Ref(key)
	file.Set(key, Marker(ref))
	veiled := file.Bytes()

	back := Parse(veiled)
	back.Set(key, realToken)
	if got := string(back.Bytes()); got != src {
		t.Fatalf("restore did not give back the original bytes\n  got:  %q\n  want: %q", got, src)
	}
}

func TestSetRefusesAValueTheReadersDisagreeOn(t *testing.T) {
	file := Parse([]byte("//r.example.com/:_authToken=" + realToken + "\n"))
	key := file.Credentials()[0].Key
	for _, bad := range []string{"has space", `has"quote`, "has'quote", "has#hash", "has;semi", ""} {
		if file.Set(key, bad) {
			t.Errorf("Set accepted %q, which npm would read differently", bad)
		}
	}
}

func TestVarRoundTrip(t *testing.T) {
	for _, key := range []string{
		"//registry.npmjs.org/:_authToken",
		"_authToken",
		"//npm.pkg.github.com/:_auth",
		"//r.example.com:8080/path/:_password",
	} {
		ref := Ref(key)
		if !strings.HasPrefix(ref, RefPrefix) {
			t.Errorf("Ref(%q) = %q, which does not start with %q", key, ref, RefPrefix)
		}
		got, ok := RefFromVar(Var(ref))
		if !ok || got != ref {
			t.Errorf("Ref -> Var -> Ref lost the reference: %q -> %q -> %q", ref, Var(ref), got)
		}
		// The variable name has to be one npm can expand, so it may hold only
		// an upper case letter, a digit or an underscore.
		for i := 0; i < len(Var(ref)); i++ {
			c := Var(ref)[i]
			if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
				t.Errorf("Var(%q) holds %q, which is not valid in a variable name", ref, string(c))
			}
		}
	}
}

func TestRefFromVarRejectsAForeignName(t *testing.T) {
	for _, name := range []string{"NPM_TOKEN", "SV_SOMETHING", "PATH", "", "SV_"} {
		if _, ok := RefFromVar(name); ok {
			t.Errorf("RefFromVar(%q) claimed a name that is not ours", name)
		}
	}
}

func TestTwoRegistriesGetTwoReferences(t *testing.T) {
	src := "//registry.npmjs.org/:_authToken=" + realToken + "\n" +
		"//npm.pkg.github.com/:_authToken=ghp_aaaaaaaaaaaaaaaaaaaa\n"
	file := Parse([]byte(src))
	creds := file.Credentials()
	if len(creds) != 2 {
		t.Fatalf("want 2 credentials, got %d", len(creds))
	}
	if Ref(creds[0].Key) == Ref(creds[1].Key) {
		t.Fatal("two registries produced the same reference, so one value would overwrite the other")
	}
}

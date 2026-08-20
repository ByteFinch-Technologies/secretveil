// Package nonetwork proves that secretveil cannot talk to a network.
//
// This is a promise the product makes and it has to be enforced by a machine,
// not by a rule in a review checklist. A secrets tool that sends anything
// anywhere is not a secrets tool. The audit log stays on the machine, there is
// no telemetry, and there is no update check.
//
// The test reads the build graph of the released binary. A package that is not
// in the graph cannot be reached at run time, whatever the code says.
package nonetwork

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// banned names a package that can move bytes off the machine, or that only
// exists to serve one that does.
var banned = []string{
	"net/http",
	"net/http/httputil",
	"net/rpc",
	"net/smtp",
	"crypto/tls",
	"golang.org/x/net/http2",
	"github.com/gorilla/websocket",
}

// allowedNet records why a package with "net" in its name is here anyway.
//
// Keep this list short and keep the reason with it. A new entry is a decision
// and it should be hard to add one by accident.
var allowedNet = map[string]string{
	"net":                                    "spf13/pflag imports it for its IP flag types. It parses an address. It never dials one.",
	"net/url":                                "the classifier reads a connection string, and the filter reads a URL out of output.",
	"net/netip":                              "pulled in by net, for the same reason.",
	"internal/nettrace":                      "pulled in by net, for the same reason. It only holds callback types.",
	"vendor/golang.org/x/net/dns/dnsmessage": "pulled in by net, for the same reason.",
}

func deps(t *testing.T) []string {
	t.Helper()
	out, err := exec.Command("go", "list", "-deps", "../../cmd/secretveil").Output()
	if err != nil {
		t.Fatalf("the build graph could not be read: %v", err)
	}
	return strings.Split(strings.TrimSpace(string(out)), "\n")
}

func TestTheBinaryCannotReachANetwork(t *testing.T) {
	graph := map[string]bool{}
	for _, p := range deps(t) {
		graph[p] = true
	}

	for _, p := range banned {
		if graph[p] {
			t.Errorf("%s is in the build graph of secretveil.\n"+
				"A secrets tool must not be able to send anything anywhere.\n"+
				"Run \"go mod why %s\" to find what pulled it in.", p, p)
		}
	}
}

// TestEveryNetworkPackageHasAReason catches the next one before it ships. A
// package arrives through a dependency of a dependency, and without this test
// nobody notices until it is already in a release.
func TestEveryNetworkPackageHasAReason(t *testing.T) {
	for _, p := range deps(t) {
		if !isNetworkish(p) {
			continue
		}
		if _, ok := allowedNet[p]; !ok {
			t.Errorf("%s is in the build graph and nobody wrote down why.\n"+
				"If it cannot move bytes off the machine, add it to allowedNet with the reason.\n"+
				"If it can, take it out of the build.", p)
		}
	}
}

func isNetworkish(p string) bool {
	for _, w := range []string{"net", "http", "socket", "grpc", "websocket", "smtp", "tls"} {
		if p == w || strings.Contains(p, "/"+w) || strings.HasPrefix(p, w+"/") {
			return true
		}
	}
	return false
}

// address finds a network address in a line of source.
var address = regexp.MustCompile(`\b(https?|wss?|ftp)://[A-Za-z0-9._~%-]+`)

// allowedHosts names a host that may appear in the source of the program.
//
// The list is a list of hosts and not a list of words, because a rule such as
// "a line that holds a slash is fine" allows every URL there is and the test
// then proves nothing.
var allowedHosts = map[string]string{
	"age-encryption.org": "named in a comment about the file format.",
	"example.com":        "a value in documentation. It is never dialled.",
	"example.org":        "a value in documentation. It is never dialled.",
	"localhost":          "a value in documentation. It is never dialled.",
	"127.0.0.1":          "a value in documentation. It is never dialled.",
	"db.internal":        "a value in documentation. It is never dialled.",
}

// modulePath is the import path of the module. The walk below turns a
// directory into an import path with it.
const modulePath = "github.com/ByteFinch-Technologies/secretveil"

// TestNoTelemetryEndpointIsCompiledIn is a second look from another angle. A
// package list cannot see a URL that a future author writes into a string.
//
// Only a file that goes into the binary is read. A test file can hold any
// address it likes, because a test file is not shipped, and so can a package
// that no command imports. The build graph decides which package that is, so
// the rule is enforced by a machine and not by a name.
func TestNoTelemetryEndpointIsCompiledIn(t *testing.T) {
	shipped := map[string]bool{}
	for _, p := range deps(t) {
		shipped[p] = true
	}
	var read, skipped int
	for _, dir := range []string{"../../cmd", "../../internal"} {
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			pkg := modulePath + "/" + filepath.ToSlash(strings.TrimPrefix(filepath.Dir(path), "../../"))
			if !shipped[pkg] {
				skipped++
				return nil
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			read++
			for i, line := range strings.Split(string(body), "\n") {
				for _, m := range address.FindAllString(line, -1) {
					host := strings.SplitN(strings.SplitN(m, "://", 2)[1], "/", 2)[0]
					if _, ok := allowedHosts[host]; ok {
						continue
					}
					t.Errorf("a network address is compiled into the program:\n"+
						"  %s:%d: %s\n"+
						"If the program must not dial it, add the host to allowedHosts with the reason.",
						path, i+1, strings.TrimSpace(line))
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("the source could not be read: %v", err)
		}
	}

	// A walk that reads nothing passes for the wrong reason. The program has
	// many source files, so a small count means the walk itself is at fault.
	if read < 10 {
		t.Errorf("only %d source files were read, so this test proves nothing. Check the walk.", read)
	}
	t.Logf("%d shipped source files were read and %d files of packages no command imports were skipped", read, skipped)
}

// TestTheWalkSkipsOnlyWhatNoCommandImports proves the skip above cannot hide a
// package that does ship. A test-only package is named here on purpose, so
// that adding an import of it from a command makes this test fail.
func TestTheWalkSkipsOnlyWhatNoCommandImports(t *testing.T) {
	shipped := map[string]bool{}
	for _, p := range deps(t) {
		shipped[p] = true
	}
	for _, p := range []string{"/internal/classify", "/internal/store", "/internal/redact", "/internal/cli"} {
		if !shipped[modulePath+p] {
			t.Errorf("%s is not in the build graph, so the walk would skip it. Check deps.", p)
		}
	}
	if shipped[modulePath+"/internal/corpus"] {
		t.Errorf("internal/corpus is in the build graph of the command.\n" +
			"It holds a labelled set of made-up credentials for the tests and must never ship.")
	}
}

// TestThePatternFindsAnAddress proves the guard above can fail.
//
// A pattern that matches nothing makes the guard silent, and a silent guard is
// the worst kind. The source of the program holds no address today, so the
// pattern is tested on a line of its own.
func TestThePatternFindsAnAddress(t *testing.T) {
	cases := map[string]string{
		`http.Post("https://telemetry.secretveil.dev/v1/events", body)`: "telemetry.secretveil.dev",
		`const updateFeed = "http://updates.example.net/latest"`:        "updates.example.net",
		`dial("wss://collector.internal:8443/stream")`:                  "collector.internal",
	}
	for line, want := range cases {
		m := address.FindString(line)
		if m == "" {
			t.Errorf("the pattern found no address in %q", line)
			continue
		}
		host := strings.SplitN(strings.SplitN(m, "://", 2)[1], "/", 2)[0]
		if host != want {
			t.Errorf("the pattern read the host of %q as %q, and it is %q", line, host, want)
		}
		if _, ok := allowedHosts[host]; ok {
			t.Errorf("%q is on the allow list and it should not be", host)
		}
	}
}

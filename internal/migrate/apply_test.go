package migrate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeStore is a store that keeps its payload in memory and can pretend to
// fail. It stands in for the encrypted file, which the migration does not
// need to know about.
type fakeStore struct {
	mu     sync.Mutex
	values map[string]string
	// failSet makes the next SetMany fail.
	failSet bool
	// corrupt makes Get return a different value for one reference.
	corrupt string
	// snapCount counts the snapshots, so a test can prove one was taken.
	snapCount int
}

func newFakeStore() *fakeStore { return &fakeStore{values: map[string]string{}} }

func (f *fakeStore) Get(_ context.Context, ref string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.values[ref]
	if !ok {
		return "", errors.New("no such reference")
	}
	if ref == f.corrupt {
		return v + "x", nil
	}
	return v, nil
}

func (f *fakeStore) SetMany(_ context.Context, values map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failSet {
		return errors.New("the store refused the write")
	}
	for k, v := range values {
		f.values[k] = v
	}
	return nil
}

func (f *fakeStore) Snapshot() ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snapCount++
	var b strings.Builder
	for k, v := range f.values {
		b.WriteString(k + "\x00" + v + "\x00")
	}
	return []byte(b.String()), nil
}

func (f *fakeStore) RestoreSnapshot(snap []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.values = map[string]string{}
	parts := strings.Split(string(snap), "\x00")
	for i := 0; i+1 < len(parts); i += 2 {
		f.values[parts[i]] = parts[i+1]
	}
	return nil
}

// project builds a temporary project from a map of relative path to content.
func project(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func read(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// The .env file for most of these tests. It holds one open value, one whole
// secret and one credential inside a longer value.
const sampleEnv = `# the service
NODE_ENV=development
PORT=3000
API_KEY=sk-live-Q9xR2mVn7pLwT4aZ
DATABASE_URL=postgres://app:s3cr3t-p4ssw0rd-x9@db.internal:5432/app
PUBLIC_URL=https://example.com
`

func TestTheMigrationReplacesTheSecretsAndKeepsTheRest(t *testing.T) {
	root := project(t, map[string]string{".env": sampleEnv})
	st := newFakeStore()

	res, err := Apply(context.Background(), st, Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	out := read(t, filepath.Join(root, ".env"))

	for _, gone := range []string{"sk-live-Q9xR2mVn7pLwT4aZ", "s3cr3t-p4ssw0rd-x9"} {
		if strings.Contains(out, gone) {
			t.Fatalf("a secret is still in the file:\n%s", out)
		}
	}
	for _, kept := range []string{"NODE_ENV=development", "PORT=3000", "# the service",
		"PUBLIC_URL=https://example.com", "postgres://app:", "@db.internal:5432/app"} {
		if !strings.Contains(out, kept) {
			t.Fatalf("the migration lost %q:\n%s", kept, out)
		}
	}
	if !strings.Contains(out, "sv://api_key") {
		t.Fatalf("the handle is missing:\n%s", out)
	}
	if !strings.Contains(out, "# sv:") {
		t.Fatalf("the shape comment is missing:\n%s", out)
	}
	if len(res.Refs) != 2 {
		t.Fatalf("the store holds %v", res.Refs)
	}
	if st.values["api_key"] != "sk-live-Q9xR2mVn7pLwT4aZ" {
		t.Fatalf("the store holds the wrong value for api_key")
	}
}

// TestASecondMigrationIsANoOp guards a real fault.
//
// The second run reads a file that already says API_KEY=sv://api_key, and the
// name rules still say that API_KEY is a secret. Without a test on the text of
// the value, the second run puts the handle itself into the store as if it
// were the value.
func TestASecondMigrationIsANoOp(t *testing.T) {
	root := project(t, map[string]string{".env": sampleEnv})
	st := newFakeStore()

	if _, err := Apply(context.Background(), st, Options{Root: root}); err != nil {
		t.Fatal(err)
	}
	after := read(t, filepath.Join(root, ".env"))
	first := map[string]string{}
	for k, v := range st.values {
		first[k] = v
	}

	// The second run has to find nothing to do.
	plan, err := BuildPlan(root)
	if err != nil {
		t.Fatal(err)
	}
	if n := plan.Counts.Partial + plan.Counts.Veiled; n != 0 {
		t.Fatalf("the second plan wants to move %d more secrets from a file that holds only handles", n)
	}

	// And if something ever calls Apply anyway, it must not change the file or
	// the store.
	res, err := Apply(context.Background(), st, Options{Root: root})
	if err == nil && len(res.Refs) != 0 {
		t.Errorf("the second run wrote %v to the store", res.Refs)
	}
	if got := read(t, filepath.Join(root, ".env")); got != after {
		t.Errorf("the second run changed the file:\nbefore\n%s\nafter\n%s", after, got)
	}
	for k, v := range first {
		if st.values[k] != v {
			t.Errorf("the second run changed the value of %s in the store", k)
		}
	}
	for k := range st.values {
		if _, ok := first[k]; !ok {
			t.Errorf("the second run added %s to the store", k)
		}
	}
}

func TestTheBackupIsGoneAfterASuccess(t *testing.T) {
	root := project(t, map[string]string{".env": sampleEnv})
	res, err := Apply(context.Background(), newFakeStore(), Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if res.Backup != "" {
		t.Fatalf("the result still names a backup at %s", res.Backup)
	}
	entries, err := os.ReadDir(filepath.Join(root, BackupRoot))
	if err == nil && len(entries) > 0 {
		t.Fatalf("a plaintext backup is still on disk: %v", entries)
	}
	// Nothing under .secretveil may hold the plaintext.
	assertNoPlaintext(t, filepath.Join(root, ".secretveil"), "sk-live-Q9xR2mVn7pLwT4aZ")
}

func TestKeepBackupLeavesTheOriginal(t *testing.T) {
	root := project(t, map[string]string{".env": sampleEnv})
	res, err := Apply(context.Background(), newFakeStore(), Options{Root: root, KeepBackup: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Backup == "" {
		t.Fatal("the result names no backup")
	}
	got := read(t, filepath.Join(res.Backup, ".env"))
	if got != sampleEnv {
		t.Fatalf("the backup does not match the original:\n%s", got)
	}
	if _, err := os.Stat(filepath.Join(res.Backup, ManifestFile)); err != nil {
		t.Fatal("the manifest is missing")
	}
}

func TestADryRunWritesNothing(t *testing.T) {
	root := project(t, map[string]string{".env": sampleEnv})
	st := newFakeStore()
	res, err := Apply(context.Background(), st, Options{Root: root, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := read(t, filepath.Join(root, ".env")); got != sampleEnv {
		t.Fatalf("the file changed:\n%s", got)
	}
	if len(st.values) != 0 {
		t.Fatalf("the store changed: %v", st.values)
	}
	if len(res.Refs) != 2 {
		t.Fatalf("the plan found %v", res.Refs)
	}
}

func TestAFailedStoreWriteLeavesTheFilesAlone(t *testing.T) {
	root := project(t, map[string]string{".env": sampleEnv})
	st := newFakeStore()
	st.failSet = true

	if _, err := Apply(context.Background(), st, Options{Root: root}); err == nil {
		t.Fatal("the migration must fail when the store refuses the write")
	}
	if got := read(t, filepath.Join(root, ".env")); got != sampleEnv {
		t.Fatalf("the file changed after a failure:\n%s", got)
	}
	assertNoBackupLeft(t, root)
}

func TestAStoreThatGivesBackTheWrongValueStopsTheMigration(t *testing.T) {
	root := project(t, map[string]string{".env": sampleEnv})
	st := newFakeStore()
	st.corrupt = "api_key"

	_, err := Apply(context.Background(), st, Options{Root: root})
	if err == nil {
		t.Fatal("the migration must fail when a value does not come back")
	}
	if !strings.Contains(err.Error(), "verify the store") {
		t.Fatalf("the error does not name the phase: %v", err)
	}
	if got := read(t, filepath.Join(root, ".env")); got != sampleEnv {
		t.Fatalf("the file changed after a failure:\n%s", got)
	}
	if len(st.values) != 0 {
		t.Fatalf("the rollback left %v in the store", st.values)
	}
	assertNoBackupLeft(t, root)
}

func TestASecretInAnotherFileIsReportedAndNotChanged(t *testing.T) {
	root := project(t, map[string]string{
		".env":               sampleEnv,
		"docker-compose.yml": "environment:\n  API_KEY: sk-live-Q9xR2mVn7pLwT4aZ\n",
	})
	res, err := Apply(context.Background(), newFakeStore(), Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Leftover) != 1 {
		t.Fatalf("the report names %v", res.Leftover)
	}
	if res.Leftover[0].Ref != "api_key" {
		t.Fatalf("the report names the wrong reference: %v", res.Leftover[0])
	}
	// The migration owns the .env files and nothing else. The other file is a
	// finding for the human, and a silent edit would be worse than a report.
	if !strings.Contains(read(t, filepath.Join(root, "docker-compose.yml")), "sk-live-Q9xR2mVn7pLwT4aZ") {
		t.Fatal("the migration changed a file it does not own")
	}
}

func TestTwoFilesThatWantOneNameGetTwoNames(t *testing.T) {
	root := project(t, map[string]string{
		"api/.env": "API_KEY=sk-live-Q9xR2mVn7pLwT4aZ\n",
		"web/.env": "API_KEY=sk-live-DIFFERENT-VALUE1\n",
	})
	st := newFakeStore()
	res, err := Apply(context.Background(), st, Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Refs) != 2 {
		t.Fatalf("the store holds %v, want two names", res.Refs)
	}
	if len(res.Renamed) != 1 {
		t.Fatalf("the rename map is %v", res.Renamed)
	}
	// Every value must survive under its own name.
	values := map[string]bool{}
	for _, v := range st.values {
		values[v] = true
	}
	if !values["sk-live-Q9xR2mVn7pLwT4aZ"] || !values["sk-live-DIFFERENT-VALUE1"] {
		t.Fatalf("a value was lost: %v", st.values)
	}
}

func TestTwoFilesWithTheSameValueShareOneName(t *testing.T) {
	root := project(t, map[string]string{
		"api/.env": "API_KEY=sk-live-Q9xR2mVn7pLwT4aZ\n",
		"web/.env": "API_KEY=sk-live-Q9xR2mVn7pLwT4aZ\n",
	})
	st := newFakeStore()
	res, err := Apply(context.Background(), st, Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Refs) != 1 || res.Refs[0] != "api_key" {
		t.Fatalf("the store holds %v, want one name", res.Refs)
	}
	if len(res.Renamed) != 0 {
		t.Fatalf("the same value in two files is not a collision: %v", res.Renamed)
	}
}

func TestTheIgnoreFileCoversTheSecretDirectory(t *testing.T) {
	root := project(t, map[string]string{
		".env":       sampleEnv,
		".git/HEAD":  "ref: refs/heads/main\n",
		".gitignore": "node_modules/\n",
	})
	if _, err := Apply(context.Background(), newFakeStore(), Options{Root: root}); err != nil {
		t.Fatal(err)
	}
	got := read(t, filepath.Join(root, ".gitignore"))
	if !strings.Contains(got, ignoreLine) {
		t.Fatalf("the ignore file does not cover the directory:\n%s", got)
	}
	if !strings.Contains(got, "node_modules/") {
		t.Fatalf("the migration lost a line from the ignore file:\n%s", got)
	}
}

func TestAProjectWithNoEnvFileIsAnError(t *testing.T) {
	root := project(t, map[string]string{"README.md": "hello\n"})
	if _, err := Apply(context.Background(), newFakeStore(), Options{Root: root}); err == nil {
		t.Fatal("a project with no .env file must be an error")
	}
}

func TestASampleFileIsNotTouched(t *testing.T) {
	sample := "API_KEY=your-key-here\n"
	root := project(t, map[string]string{".env": sampleEnv, ".env.example": sample})
	if _, err := Apply(context.Background(), newFakeStore(), Options{Root: root}); err != nil {
		t.Fatal(err)
	}
	if got := read(t, filepath.Join(root, ".env.example")); got != sample {
		t.Fatalf("the migration changed the sample file:\n%s", got)
	}
}

// assertNoBackupLeft proves a failed migration left no plaintext behind.
func assertNoBackupLeft(t *testing.T, root string) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(root, BackupRoot))
	if err == nil && len(entries) > 0 {
		t.Fatalf("the rollback left a plaintext backup: %v", entries)
	}
}

// assertNoPlaintext walks a directory and fails if any file holds the needle.
func assertNoPlaintext(t *testing.T, dir, needle string) {
	t.Helper()
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		if strings.Contains(string(body), needle) {
			t.Fatalf("%s holds the plaintext secret", path)
		}
		return nil
	})
}

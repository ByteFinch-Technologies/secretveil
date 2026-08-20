package migrate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ByteFinch-Technologies/secretveil/internal/classify"
	"github.com/ByteFinch-Technologies/secretveil/internal/envfile"
	"github.com/ByteFinch-Technologies/secretveil/internal/npmrc"
)

// Phase names one step of the migration. Each phase can be undone, and a
// failure in any phase undoes every phase before it.
type Phase int

const (
	PhasePlan Phase = iota + 1
	PhaseBackup
	PhaseWriteSecrets
	PhaseVerifyStore
	PhaseRewrite
	PhaseIgnore
	PhaseVerifyTree
	PhaseDone
)

func (p Phase) String() string {
	switch p {
	case PhasePlan:
		return "plan"
	case PhaseBackup:
		return "backup"
	case PhaseWriteSecrets:
		return "write the secrets"
	case PhaseVerifyStore:
		return "verify the store"
	case PhaseRewrite:
		return "rewrite the files"
	case PhaseIgnore:
		return "update the ignore files"
	case PhaseVerifyTree:
		return "verify the tree"
	case PhaseDone:
		return "done"
	}
	return "unknown"
}

// SecretStore is the part of a store that the migration needs.
//
// Snapshot and RestoreSnapshot let the migration undo a write. A backend that
// cannot do this cannot be a migration target, because a half written store is
// worse than no store.
type SecretStore interface {
	Get(ctx context.Context, ref string) (string, error)
	SetMany(ctx context.Context, values map[string]string) error
	Snapshot() ([]byte, error)
	RestoreSnapshot(snap []byte) error
}

// Options controls a migration.
type Options struct {
	// Root is the top of the project.
	Root string
	// DryRun stops after the plan and writes nothing.
	DryRun bool
	// Log receives one line per step. It may be nil.
	Log func(p Phase, msg string)
	// SkipIgnore leaves .gitignore alone.
	SkipIgnore bool
	// KeepBackup leaves the plaintext backup on disk after a success.
	//
	// The default removes it, and this is deliberate. The backup holds the
	// original files, and the original files hold the secrets in plaintext. To
	// keep it would undo the whole point of the migration. The migration needs
	// the backup only while it runs, so that a failure in a later phase can
	// put every file back.
	//
	// A backup is not the way to undo a migration later. Use restore, which
	// reads the handles and puts the values back from the store.
	KeepBackup bool
}

// Leftover is a place where an original secret value still appears after the
// migration.
type Leftover struct {
	Path string `json:"path"`
	Ref  string `json:"ref"`
	Line int    `json:"line"`
}

// Result reports what the migration did.
type Result struct {
	Plan *Plan `json:"plan"`
	// Backup is the directory that holds the original files.
	Backup string `json:"backup"`
	// Refs names every reference that went into the store.
	Refs []string `json:"refs"`
	// Rewritten names every file that changed.
	Rewritten []string `json:"rewritten"`
	// Leftover names every other file in the tree that still holds a secret.
	// These are not a failure of the migration. They are a finding, and the
	// human must deal with each one.
	Leftover []Leftover `json:"leftover,omitempty"`
	// Renamed lists every reference that had to take a new name, because two
	// variables in different files wanted the same one.
	//
	// This is a list and not a map from the old name to the new one. Three
	// files may hold the same key, and then one old name becomes two new
	// names. A map lost the first of them, so init told the developer about
	// one rename when it had made two.
	Renamed []Rename `json:"renamed,omitempty"`
}

// Rename is one reference that had to take a new name.
type Rename struct {
	// From is the name the reference would have had.
	From string `json:"from"`
	// To is the name it took.
	To string `json:"to"`
	// File is the file that holds it, relative to the root. It is the reason
	// the name changed, so the report has to show it.
	File string `json:"file"`
}

// undo is one step of the rollback.
type undo struct {
	what string
	fn   func() error
}

// Apply runs the whole migration. On any failure it puts the project back the
// way it was and returns an error that names the phase.
func Apply(ctx context.Context, st SecretStore, opt Options) (*Result, error) {
	root := opt.Root
	if root == "" {
		root = "."
	}
	logf := func(p Phase, format string, a ...any) {
		if opt.Log != nil {
			opt.Log(p, fmt.Sprintf(format, a...))
		}
	}

	var steps []undo
	rollback := func(cause error, at Phase) error {
		var failed []string
		for i := len(steps) - 1; i >= 0; i-- {
			if err := steps[i].fn(); err != nil {
				failed = append(failed, fmt.Sprintf("%s: %v", steps[i].what, err))
			}
		}
		if len(failed) == 0 {
			return fmt.Errorf("the phase %q failed and the project is unchanged: %w", at, cause)
		}
		return fmt.Errorf("the phase %q failed, and the rollback did not finish.\n"+
			"These steps need your attention:\n  %s\nThe first fault was: %w",
			at, strings.Join(failed, "\n  "), cause)
	}

	// Phase 1. Plan. Nothing is written.
	plan, err := BuildPlan(root)
	if err != nil {
		return nil, fmt.Errorf("the phase %q failed: %w", PhasePlan, err)
	}
	if len(plan.Files) == 0 {
		return nil, errors.New("there is no .env or .npmrc file with values here")
	}
	secrets, err := plan.Secrets(os.ReadFile)
	if err != nil {
		return nil, fmt.Errorf("the phase %q failed: %w", PhasePlan, err)
	}
	renamed := resolveCollisions(plan, root)
	if len(renamed) > 0 {
		// The names changed, so read the values again under the new names.
		secrets, err = plan.Secrets(os.ReadFile)
		if err != nil {
			return nil, fmt.Errorf("the phase %q failed: %w", PhasePlan, err)
		}
	}
	res := &Result{Plan: plan, Refs: sortedKeys(secrets), Renamed: renamed}
	logf(PhasePlan, "%d file(s), %d secret(s)", len(plan.Files), len(secrets))

	if len(secrets) == 0 {
		return res, errors.New("no variable here needs a handle, so there is nothing to do")
	}
	if opt.DryRun {
		return res, nil
	}

	// Phase 2. Backup. Every file goes to a directory under .secretveil, with
	// a hash of each one, before anything changes.
	backup, err := makeBackup(root, plan)
	if err != nil {
		return res, rollback(err, PhaseBackup)
	}
	res.Backup = backup
	steps = append(steps, undo{"remove the backup " + backup, func() error { return os.RemoveAll(backup) }})
	logf(PhaseBackup, "the originals are in %s", rel(root, backup))

	// Phase 3. Write the secrets. The snapshot is the whole encrypted file, so
	// an undo puts back exactly what was there, including an absent file.
	snap, err := st.Snapshot()
	if err != nil {
		return res, rollback(err, PhaseWriteSecrets)
	}
	if err := st.SetMany(ctx, secrets); err != nil {
		return res, rollback(err, PhaseWriteSecrets)
	}
	steps = append(steps, undo{"put the secret store back", func() error { return st.RestoreSnapshot(snap) }})
	logf(PhaseWriteSecrets, "%d secret(s) are in the store", len(secrets))

	// Phase 4. Verify the store. Every value must come back byte for byte
	// before any .env file is touched. This is the step that makes the rewrite
	// safe, because after the rewrite the store is the only copy.
	for _, ref := range res.Refs {
		got, err := st.Get(ctx, ref)
		if err != nil {
			return res, rollback(fmt.Errorf("the store does not hold %s: %w", ref, err), PhaseVerifyStore)
		}
		if got != secrets[ref] {
			return res, rollback(fmt.Errorf("the store gave back a different value for %s", ref), PhaseVerifyStore)
		}
	}
	logf(PhaseVerifyStore, "every value came back from the store")

	// Phase 5. Rewrite the .env files.
	for _, f := range plan.Files {
		original, err := os.ReadFile(f.Path)
		if err != nil {
			return res, rollback(err, PhaseRewrite)
		}
		out, changed, err := rewrite(original, f)
		if err != nil {
			return res, rollback(fmt.Errorf("%s: %w", f.Path, err), PhaseRewrite)
		}
		if !changed {
			continue
		}
		if err := writeAtomic(f.Path, out, fileMode(f.Path)); err != nil {
			return res, rollback(fmt.Errorf("%s: %w", f.Path, err), PhaseRewrite)
		}
		path, body := f.Path, original
		steps = append(steps, undo{"put back " + rel(root, path), func() error {
			return writeAtomic(path, body, fileMode(path))
		}})
		res.Rewritten = append(res.Rewritten, f.Path)
	}
	logf(PhaseRewrite, "%d file(s) now hold handles", len(res.Rewritten))

	// Phase 6. Ignore files. The encrypted file must never reach a commit.
	if !opt.SkipIgnore {
		restore, err := addIgnore(root)
		if err != nil {
			return res, rollback(err, PhaseIgnore)
		}
		if restore != nil {
			steps = append(steps, undo{"put back .gitignore", restore})
			logf(PhaseIgnore, ".gitignore now covers %s", ignoreLine)
		}
	}

	// Phase 7. Verify the tree. Every original value must be gone from every
	// file this migration rewrote. A value that survives anywhere else in the
	// tree is a finding for the human, not a fault of the migration.
	rewritten := map[string]bool{}
	for _, p := range res.Rewritten {
		rewritten[p] = true
	}
	found, err := searchTree(root, secrets)
	if err != nil {
		return res, rollback(err, PhaseVerifyTree)
	}
	for _, l := range found {
		if rewritten[l.Path] {
			return res, rollback(
				fmt.Errorf("%s still holds the value of %s at line %d", rel(root, l.Path), l.Ref, l.Line),
				PhaseVerifyTree)
		}
	}
	res.Leftover = found
	logf(PhaseVerifyTree, "no rewritten file holds a secret; %d other place(s) still do", len(found))

	// The backup holds plaintext. It goes away now that every phase is past.
	if !opt.KeepBackup {
		if err := os.RemoveAll(backup); err != nil {
			logf(PhaseDone, "warning: the plaintext backup at %s could not be removed: %v", rel(root, backup), err)
		} else {
			res.Backup = ""
		}
	}
	logf(PhaseDone, "the migration is complete")
	return res, nil
}

// rewrite turns the plaintext of one file into the reference form.
func rewrite(src []byte, f FilePlan) ([]byte, bool, error) {
	if f.kind() == KindNpmrc {
		return rewriteNpmrc(src, f)
	}
	return rewriteDotenv(src, f)
}

// rewriteNpmrc puts a ${SV_NPMRC_...} marker in place of each credential.
//
// There is no shape comment here. npm reads this file with its own parser, and
// a comment this tool invented could change what npm sees. The shape is of
// little use in this file in any case: nobody writes code against a registry
// token, they only need npm to authenticate.
//
// Each entry names a line and not a key, because an .npmrc file may name the
// same key twice. The key on that line is checked before the write, so a file
// that changed since the plan was built stops the migration instead of losing
// a value.
func rewriteNpmrc(src []byte, f FilePlan) ([]byte, bool, error) {
	parsed := npmrc.Parse(src)
	changed := false
	for _, e := range f.Entries {
		if e.Decision.Class == classify.Open {
			continue
		}
		if e.Line < 1 || e.Line > len(parsed.Lines) {
			return nil, false, fmt.Errorf("line %d is gone from the file", e.Line)
		}
		line := &parsed.Lines[e.Line-1]
		if line.Key != e.Key {
			return nil, false, fmt.Errorf("line %d now holds %q and not %q", e.Line, line.Key, e.Key)
		}
		if !line.Set(e.Projected) {
			return nil, false, fmt.Errorf("the value of %s on line %d could not be replaced", e.Key, e.Line)
		}
		changed = true
	}
	if !changed {
		return src, false, nil
	}
	return parsed.Bytes(), true, nil
}

// rewriteDotenv puts an sv:// handle in place of each secret.
func rewriteDotenv(src []byte, f FilePlan) ([]byte, bool, error) {
	parsed := envfile.Parse(src)
	inline := map[string]string{}
	for _, line := range parsed.Assignments() {
		inline[line.Key] = line.Inline
	}

	changed := false
	for _, e := range f.Entries {
		if e.Decision.Class == classify.Open {
			continue
		}
		if !parsed.Set(e.Key, e.Projected) {
			return nil, false, fmt.Errorf("the key %s is gone from the file", e.Key)
		}
		// The shape comment tells a reader, and an AI tool, what kind of value
		// the handle stands for. It holds no part of the value itself.
		//
		// A line that already has a comment keeps it. The comment belongs to
		// the developer, and restore must be able to give back the file it
		// started from, byte for byte.
		if strings.TrimSpace(inline[e.Key]) == "" {
			parsed.SetInline(e.Key, e.Decision.Shape.Comment())
		}
		changed = true
	}
	if !changed {
		return src, false, nil
	}
	return parsed.Bytes(), true, nil
}

// resolveCollisions gives a new name to a reference that two variables claim
// with two different values.
//
// A reference that two variables claim with the same value is not a collision.
// One name for one value is correct, and it is what a developer expects when
// the same database password appears in two services.
func resolveCollisions(p *Plan, root string) []Rename {
	type owner struct {
		file  int
		entry int
		span  int
		// part is the piece of the value that the span covers.
		part string
		// full is the whole value of the variable. The projected text is built
		// from it again after a rename.
		full string
	}
	owners := map[string][]owner{}

	for fi, f := range p.Files {
		src, err := os.ReadFile(f.Path)
		if err != nil {
			continue
		}
		for ei, e := range f.Entries {
			v, ok := entryValue(f.kind(), src, e)
			if !ok {
				continue
			}
			for si, s := range e.Decision.Spans {
				if s.Start < 0 || s.End > len(v) || s.Start > s.End {
					continue
				}
				owners[s.Ref] = append(owners[s.Ref], owner{fi, ei, si, v[s.Start:s.End], v})
			}
		}
	}

	taken := map[string]bool{}
	for ref := range owners {
		taken[ref] = true
	}
	var renamed []Rename

	refs := make([]string, 0, len(owners))
	for ref := range owners {
		refs = append(refs, ref)
	}
	sort.Strings(refs)

	for _, ref := range refs {
		list := owners[ref]
		if len(list) < 2 {
			continue
		}
		same := true
		for _, o := range list[1:] {
			if o.part != list[0].part {
				same = false
				break
			}
		}
		if same {
			continue
		}
		// The first owner keeps the plain name. Every other owner gets the
		// name of its file in front, so the new name still reads well.
		for _, o := range list[1:] {
			kind := p.Files[o.file].kind()
			where := rel(root, p.Files[o.file].Path)
			base := renameRef(kind, ref, fileTag(kind, where))
			name := base
			for n := 2; taken[name]; n++ {
				name = fmt.Sprintf("%s_%d", base, n)
			}
			taken[name] = true
			renamed = append(renamed, Rename{From: ref, To: name, File: where})
			entry := &p.Files[o.file].Entries[o.entry]
			entry.Decision.Spans[o.span].Ref = name
			refreshEntry(p.Files[o.file].kind(), entry, o.full)
		}
	}
	return renamed
}

// renameRef builds a new reference that names the file it came from.
//
// A reference from an .npmrc file must keep the npmrc_ prefix. That prefix is
// the only thing that tells restore and run that a ${SV_...} marker is one this
// tool wrote. A rename that put the file name in front of it made restore walk
// past the marker and leave it on disk, so the developer got a file that npm
// could not use.
func renameRef(kind FileKind, ref, from string) string {
	if kind == KindNpmrc {
		return npmrc.RefPrefix + from + "_" + strings.TrimPrefix(ref, npmrc.RefPrefix)
	}
	return from + "_" + ref
}

// refreshEntry rebuilds the projected text and the reference list of an entry
// after a span changed. The rewrite writes the projected text into the file,
// so a rename that misses it puts the wrong handle on disk.
//
// The two kinds of file do not take the same text. A .env file takes an sv://
// handle around the span. An .npmrc file takes a ${SV_NPMRC_...} marker, and the
// whole value is always one span, so the marker of that span is the whole line.
func refreshEntry(kind FileKind, e *Entry, value string) {
	e.Refs = e.Refs[:0]
	for _, s := range e.Decision.Spans {
		e.Refs = append(e.Refs, s.Ref)
	}
	if kind == KindNpmrc {
		if len(e.Decision.Spans) == 1 {
			e.Projected = npmrc.Marker(e.Decision.Spans[0].Ref)
		}
		return
	}
	e.Projected = classify.Project(value, e.Decision)
}

// fileTag builds the part of a new reference name that says which file the
// value came from.
//
// A .env file keeps its whole name. The word after "env." is the name of the
// environment, and it is the most useful word in the file name. An earlier
// build cut the name at the last dot, so ".env.local" and ".env.development"
// both became "env". Two files that held the same key then had to be told
// apart by a number, and the developer read "env_api_key" and "env_api_key_2"
// with no way to know which file was which.
//
// An .npmrc file keeps only its directory. Every .npmrc has the same base
// name, so that name says nothing, and the reference already starts with
// "npmrc_". An .npmrc at the top of the project has no directory to name, and
// takes the word "root" instead.
func fileTag(kind FileKind, rel string) string {
	if kind != KindNpmrc {
		return slug(rel)
	}
	if tag := slug(filepath.Dir(rel)); tag != "" {
		return tag
	}
	return "root"
}

// slug turns a path into a name that a reference can hold. It changes the
// characters and nothing else. The caller decides which part of the path to
// pass in.
func slug(path string) string {
	var b strings.Builder
	last := byte('_')
	for i := 0; i < len(path); i++ {
		c := path[i]
		switch {
		case c >= 'A' && c <= 'Z':
			c += 'a' - 'A'
			fallthrough
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			b.WriteByte(c)
			last = c
		default:
			if last != '_' {
				b.WriteByte('_')
				last = '_'
			}
		}
	}
	return strings.Trim(b.String(), "_")
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func rel(root, path string) string {
	if r, err := filepath.Rel(root, path); err == nil {
		return r
	}
	return path
}

// fileMode returns the permissions of an existing file, or 0600.
func fileMode(path string) os.FileMode {
	if fi, err := os.Stat(path); err == nil {
		return fi.Mode().Perm()
	}
	return 0o600
}

// writeAtomic replaces a file in one step. A reader sees the old file or the
// new file, and never a half written one.
func writeAtomic(path string, body []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".secretveil-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)

	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// Manifest records a backup.
type Manifest struct {
	Root    string            `json:"root"`
	Made    string            `json:"made"`
	Version string            `json:"version"`
	Files   map[string]string `json:"files"`
}

// ManifestFile is the name of the record inside a backup directory.
const ManifestFile = "manifest.json"

// BackupRoot is the directory that holds every backup.
const BackupRoot = ".secretveil/backup"

// makeBackup copies every file in the plan and records a hash of each one.
func makeBackup(root string, p *Plan) (string, error) {
	dir := filepath.Join(root, BackupRoot, time.Now().UTC().Format("20060102-150405"))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	m := Manifest{
		Root:  root,
		Made:  time.Now().UTC().Format(time.RFC3339),
		Files: map[string]string{},
	}
	for _, f := range p.Files {
		body, err := os.ReadFile(f.Path)
		if err != nil {
			return "", err
		}
		name := rel(root, f.Path)
		dst := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return "", err
		}
		if err := os.WriteFile(dst, body, 0o600); err != nil {
			return "", err
		}
		sum := sha256.Sum256(body)
		m.Files[name] = hex.EncodeToString(sum[:])
	}
	body, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, ManifestFile), append(body, '\n'), 0o600); err != nil {
		return "", err
	}
	return dir, nil
}

// ignoreLine is what goes into .gitignore.
const ignoreLine = ".secretveil/"

// addIgnore puts the secretveil directory in .gitignore. It returns a function
// that puts the file back, or nil when the file already covered it.
func addIgnore(root string) (func() error, error) {
	if _, err := os.Stat(filepath.Join(root, ".git")); err != nil {
		// This is not a git repository, so there is nothing to ignore.
		return nil, nil
	}
	path := filepath.Join(root, ".gitignore")
	old, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	existed := err == nil
	for _, line := range strings.Split(string(old), "\n") {
		if strings.TrimSpace(line) == ignoreLine {
			return nil, nil
		}
	}
	body := string(old)
	if body != "" && !strings.HasSuffix(body, "\n") {
		body += "\n"
	}
	body += "\n# secretveil keeps the encrypted secrets here.\n" + ignoreLine + "\n"
	if err := writeAtomic(path, []byte(body), 0o644); err != nil {
		return nil, err
	}
	return func() error {
		if !existed {
			return os.Remove(path)
		}
		return writeAtomic(path, old, 0o644)
	}, nil
}

// maxSearchSize is the largest file the tree search reads. A file above it is
// a build product or a data set, and reading it would make init slow.
const maxSearchSize = 4 << 20

// SearchTree looks for every secret value in every file under root.
//
// It is exported for doctor, which had asked the classifier whether a file
// held a plaintext secret. That question is circular: a value the classifier
// failed to recognise is a value the classifier reports as safe, so the one
// fault the check exists to find is the one fault it could never report. This
// function asks the file instead, and a file cannot be talked round.
//
// Two limits are deliberate. A value shorter than six characters is skipped,
// because ordinary text holds a short string by accident and the report would
// be noise. A file larger than maxSearchSize is skipped, because it is a build
// product or a data set and reading it would make the command slow.
//
// The result never holds a value, only the place where one was found.
func SearchTree(root string, secrets map[string]string) ([]Leftover, error) {
	return searchTree(root, secrets)
}

// searchTree looks for every secret value in every file under root.
func searchTree(root string, secrets map[string]string) ([]Leftover, error) {
	refs := sortedKeys(secrets)
	var out []Leftover

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if path != root && skipDir[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() > maxSearchSize {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		text := string(body)
		for _, ref := range refs {
			v := secrets[ref]
			// A short value gives a false report, because ordinary text holds
			// it by accident. The filter skips a short value as well.
			if len(v) < 6 {
				continue
			}
			if i := strings.Index(text, v); i >= 0 {
				out = append(out, Leftover{Path: path, Ref: ref, Line: 1 + strings.Count(text[:i], "\n")})
			}
		}
		return nil
	})
	return out, err
}

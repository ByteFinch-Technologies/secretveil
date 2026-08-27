// Package migrate turns a repository that holds plaintext secrets into a
// repository that holds handles. Phase 1 of that work is the plan, and the
// plan writes nothing. It is safe to run at any time.
package migrate

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ByteFinch-Technologies/secretveil/internal/classify"
	"github.com/ByteFinch-Technologies/secretveil/internal/envfile"
	"github.com/ByteFinch-Technologies/secretveil/internal/handle"
	"github.com/ByteFinch-Technologies/secretveil/internal/npmrc"
	"github.com/ByteFinch-Technologies/secretveil/internal/shape"
)

// skipDir names a directory that never holds a project secret file.
var skipDir = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true,
	"build": true, ".next": true, ".nuxt": true, "target": true,
	"__pycache__": true, ".venv": true, "venv": true, ".secretveil": true,
	"coverage": true, ".terraform": true,
}

// SkipDir reports whether a directory name is one that never holds a project
// secret file. Every scanner in the program uses this one list, so a directory
// that one check walks past is a directory every check walks past.
func SkipDir(name string) bool { return skipDir[name] }

// sampleSuffix names a file that holds placeholders, not values.
var sampleSuffix = []string{".example", ".sample", ".template", ".dist", ".defaults"}

// FileKind says which parser reads a file, and which form of reference goes
// into it.
type FileKind string

const (
	// KindDotenv is a .env file. It takes an sv:// handle, because every
	// framework lets a variable in the environment beat the file.
	KindDotenv FileKind = "dotenv"
	// KindNpmrc is an .npmrc file. It takes a ${SV_NPMRC_...} marker instead.
	// npm reads the file straight from disk and has no precedence rule, so a
	// handle would go to the registry as if it were the token. npm does expand
	// a variable from the environment, and that is the opening this uses.
	KindNpmrc FileKind = "npmrc"
)

// Entry is one variable in one file.
type Entry struct {
	Key       string            `json:"key"`
	Decision  classify.Decision `json:"decision"`
	Projected string            `json:"projected"`
	Refs      []string          `json:"refs"`
	// Line is the 1-based line of the record. The tool addresses both file
	// kinds by position. A file can name the same key twice, and a rewrite
	// that goes by name could touch the wrong line and leave the live token on
	// disk. A zero is never valid. entryValue refuses it, and rewriteDotenv
	// returns an error.
	Line int `json:"line,omitempty"`
}

// FilePlan is the work for one file.
type FilePlan struct {
	Path    string   `json:"path"`
	Kind    FileKind `json:"kind"`
	Entries []Entry  `json:"entries"`
}

// kind returns the kind of a file plan, and treats an unset value as a .env
// file so a plan decoded from an older run still reads correctly.
func (f FilePlan) kind() FileKind {
	if f.Kind == "" {
		return KindDotenv
	}
	return f.Kind
}

// Counts summarises a plan.
type Counts struct {
	Files   int `json:"files"`
	Open    int `json:"open"`
	Partial int `json:"partial"`
	Veiled  int `json:"veiled"`
	// Review counts the values that stay open and that a person should read.
	// It is not a fourth class. Every one of them is already counted in Open.
	Review int `json:"review,omitempty"`
}

// Unrecognised is one value that stays in the file and that still reads like a
// credential. It never holds the value, only the place and the reason.
type Unrecognised struct {
	Path   string `json:"path"`
	Key    string `json:"key"`
	Reason string `json:"reason"`
}

// Plan is the whole migration, before any write happens.
type Plan struct {
	Root   string     `json:"root"`
	Files  []FilePlan `json:"files"`
	Counts Counts     `json:"counts"`
	// Links names every .env file that is a symbolic link. The program never
	// follows one. The developer has to deal with each one by hand.
	Links []string `json:"links,omitempty"`
}

// Unrecognised lists every value that the classifier left open and then marked
// for a person to read.
//
// The order is the order of the plan, so the report reads in the same order as
// the table above it. Both init and doctor call this, because a list that each
// of them built for itself would be two lists, and the one a developer trusted
// would be whichever they read last.
func (p *Plan) Unrecognised() []Unrecognised {
	var out []Unrecognised
	for _, f := range p.Files {
		for _, e := range f.Entries {
			if e.Decision.Review {
				out = append(out, Unrecognised{Path: f.Path, Key: e.Key, Reason: e.Decision.Reason})
			}
		}
	}
	return out
}

// entryValue returns the value that one planned entry names, read from the
// bytes of its file.
//
// Every kind of file is addressed by record, because a .env file and an .npmrc
// file may both name the same key twice, and only the position says which
// record holds which value. Reading a .env file by key gave the last value to
// every record of that key. The first value then reached neither the store nor
// the rewrite, and it stayed in the file in the clear.
func entryValue(kind FileKind, src []byte, e Entry) (string, bool) {
	if kind == KindNpmrc {
		lines := npmrc.Parse(src).Lines
		if e.Line < 1 || e.Line > len(lines) {
			return "", false
		}
		line := lines[e.Line-1]
		if line.Key != e.Key {
			// The file changed under the plan. Touching it now would rewrite
			// the wrong record.
			return "", false
		}
		return line.Value, true
	}
	lines := envfile.Parse(src).Lines
	if e.Line < 1 || e.Line > len(lines) {
		return "", false
	}
	line := lines[e.Line-1]
	if line.Kind != envfile.Assignment || line.Key != e.Key {
		return "", false
	}
	return line.Value, true
}

// Secrets returns the reference and the real value of everything that must go
// into the store. The caller must not log this map.
func (p *Plan) Secrets(read func(path string) ([]byte, error)) (map[string]string, error) {
	out := map[string]string{}
	for _, f := range p.Files {
		src, err := read(f.Path)
		if err != nil {
			return nil, err
		}
		for _, e := range f.Entries {
			if e.Decision.Class == classify.Open {
				continue
			}
			value, ok := entryValue(f.kind(), src, e)
			if !ok {
				continue
			}
			for _, span := range e.Decision.Spans {
				if span.Start < 0 || span.End > len(value) || span.Start > span.End {
					continue
				}
				part := value[span.Start:span.End]
				// One reference must name one value. A second value under the
				// same name would replace the first here, and the first would
				// then reach neither the store nor the check that searches the
				// tree for it. resolveCollisions gives a new name to every
				// owner after the first, so this cannot happen. It is checked
				// because the cost of a miss is a secret left in the clear.
				if old, seen := out[span.Ref]; seen && old != part {
					return nil, fmt.Errorf(
						"the reference %s names two different values, so one of them would be lost", span.Ref)
				}
				out[span.Ref] = part
			}
		}
	}
	return out, nil
}

// IsSecretFile reports whether a base name is a .env file that holds values.
func IsSecretFile(base string) bool {
	if base != ".env" && !strings.HasPrefix(base, ".env.") {
		return false
	}
	for _, s := range sampleSuffix {
		if strings.HasSuffix(base, s) {
			return false
		}
	}
	return true
}

// Discover finds every .env file under a root.
func Discover(root string) ([]string, error) {
	found, _, err := discover(root)
	return pathsOfKind(found, KindDotenv), err
}

// DiscoverNpmrc finds every .npmrc file under a root.
func DiscoverNpmrc(root string) ([]string, error) {
	found, _, err := discover(root)
	return pathsOfKind(found, KindNpmrc), err
}

// candidate is one file the migration may work on.
type candidate struct {
	path string
	kind FileKind
}

func pathsOfKind(list []candidate, kind FileKind) []string {
	var out []string
	for _, c := range list {
		if c.kind == kind {
			out = append(out, c.path)
		}
	}
	return out
}

// kindOf returns the kind of a base name, and false when the file is not one
// this program works on.
func kindOf(base string) (FileKind, bool) {
	switch {
	case IsSecretFile(base):
		return KindDotenv, true
	case npmrc.IsFile(base):
		return KindNpmrc, true
	}
	return "", false
}

// discover returns the files to work on, and the symbolic links it refused to
// follow.
//
// A symbolic link is never followed, and this is a security rule and not a
// convenience. A file named .env in the project can point at any file on the
// machine. If the program followed it, then init would read that file, decide
// which of its lines look like secrets, and write a rewritten copy inside the
// project. That would move content from outside the project to inside it, which
// is the opposite of what this tool is for.
func discover(root string) (found []candidate, links []string, err error) {
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, werr error) error {
		if werr != nil {
			return nil
		}
		if d.IsDir() {
			if path != root && skipDir[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		kind, ok := kindOf(d.Name())
		if !ok {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			links = append(links, path)
			return nil
		}
		found = append(found, candidate{path: path, kind: kind})
		return nil
	})
	sort.Slice(found, func(i, j int) bool { return found[i].path < found[j].path })
	sort.Strings(links)
	return found, links, err
}

// BuildPlan reads every candidate file and classifies every variable. It
// writes nothing.
func BuildPlan(root string) (*Plan, error) {
	paths, links, err := discover(root)
	if err != nil {
		return nil, err
	}
	p := &Plan{Root: root, Links: links}
	for _, c := range paths {
		src, err := os.ReadFile(c.path)
		if err != nil {
			continue
		}
		fp := FilePlan{Path: c.path, Kind: c.kind}
		if c.kind == KindNpmrc {
			fp.Entries = planNpmrc(src)
		} else {
			fp.Entries = planDotenv(src)
		}
		for _, e := range fp.Entries {
			if e.Decision.Review {
				p.Counts.Review++
			}
			switch e.Decision.Class {
			case classify.Open:
				p.Counts.Open++
			case classify.Partial:
				p.Counts.Partial++
			default:
				p.Counts.Veiled++
			}
		}
		if len(fp.Entries) > 0 {
			p.Files = append(p.Files, fp)
			p.Counts.Files++
		}
	}
	return p, nil
}

// planDotenv classifies every variable in a .env file.
//
// Each entry names a record and not a key. A .env file may name the same key
// twice, and each of the two records may hold a different secret.
func planDotenv(src []byte) []Entry {
	var out []Entry
	lines := envfile.Parse(src).Lines
	for i := range lines {
		line := &lines[i]
		if line.Kind != envfile.Assignment {
			continue
		}
		d := classify.Classify(line.Key, line.Value)
		refs := make([]string, 0, len(d.Spans))
		for _, s := range d.Spans {
			refs = append(refs, s.Ref)
		}
		out = append(out, Entry{
			Key:       line.Key,
			Decision:  d,
			Projected: classify.Project(line.Value, d),
			Refs:      refs,
			Line:      i + 1,
		})
	}
	return out
}

// planNpmrc finds every registry credential in an .npmrc file.
//
// Only a line the npmrc package calls a credential becomes an entry. An
// ordinary setting such as a registry address is not planned at all, because
// npm needs to read it as it stands and there is nothing to hide in it.
func planNpmrc(src []byte) []Entry {
	var out []Entry
	lines := npmrc.Parse(src).Lines
	for i := range lines {
		line := &lines[i]
		if !line.IsCredential() {
			continue
		}
		ref := npmrc.Ref(line.Key)
		out = append(out, Entry{
			Key: line.Key,
			Decision: classify.Decision{
				Class: classify.Veiled,
				Spans: []handle.Span{{Start: 0, End: len(line.Value), Ref: ref}},
				Shape: shape.Of(line.Value),
				Rule:  "npmrc-auth",
			},
			Projected: npmrc.Marker(ref),
			Refs:      []string{ref},
			Line:      i + 1,
		})
	}
	return out
}

// DuplicateRefs returns any reference that two different variables would claim.
// The init flow must resolve these before it writes anything to the store.
func (p *Plan) DuplicateRefs() map[string][]string {
	owners := map[string][]string{}
	for _, f := range p.Files {
		for _, e := range f.Entries {
			for _, ref := range e.Refs {
				owner := f.Path + ":" + e.Key
				owners[ref] = append(owners[ref], owner)
			}
		}
	}
	dupes := map[string][]string{}
	for ref, list := range owners {
		if len(list) > 1 {
			dupes[ref] = list
		}
	}
	return dupes
}

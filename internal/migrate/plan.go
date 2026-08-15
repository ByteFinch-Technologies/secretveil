// Package migrate turns a repository that holds plaintext secrets into a
// repository that holds handles. Phase 1 of that work is the plan, and the
// plan writes nothing. It is safe to run at any time.
package migrate

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ByteFinch-Technologies/secretveil/internal/classify"
	"github.com/ByteFinch-Technologies/secretveil/internal/envfile"
)

// skipDir names a directory that never holds a project secret file.
var skipDir = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true,
	"build": true, ".next": true, ".nuxt": true, "target": true,
	"__pycache__": true, ".venv": true, "venv": true, ".secretveil": true,
	"coverage": true, ".terraform": true,
}

// sampleSuffix names a file that holds placeholders, not values.
var sampleSuffix = []string{".example", ".sample", ".template", ".dist", ".defaults"}

// Entry is one variable in one file.
type Entry struct {
	Key       string            `json:"key"`
	Decision  classify.Decision `json:"decision"`
	Projected string            `json:"projected"`
	Refs      []string          `json:"refs"`
}

// FilePlan is the work for one file.
type FilePlan struct {
	Path    string  `json:"path"`
	Entries []Entry `json:"entries"`
}

// Counts summarises a plan.
type Counts struct {
	Files   int `json:"files"`
	Open    int `json:"open"`
	Partial int `json:"partial"`
	Veiled  int `json:"veiled"`
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

// Secrets returns the reference and the real value of everything that must go
// into the store. The caller must not log this map.
func (p *Plan) Secrets(read func(path string) ([]byte, error)) (map[string]string, error) {
	out := map[string]string{}
	for _, f := range p.Files {
		src, err := read(f.Path)
		if err != nil {
			return nil, err
		}
		parsed := envfile.Parse(src)
		for _, e := range f.Entries {
			if e.Decision.Class == classify.Open {
				continue
			}
			value, ok := parsed.Get(e.Key)
			if !ok {
				continue
			}
			for _, span := range e.Decision.Spans {
				if span.Start < 0 || span.End > len(value) || span.Start > span.End {
					continue
				}
				out[span.Ref] = value[span.Start:span.End]
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

// Discover finds every candidate file under a root.
func Discover(root string) ([]string, error) {
	found, _, err := discover(root)
	return found, err
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
func discover(root string) (found, links []string, err error) {
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
		if !IsSecretFile(d.Name()) {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			links = append(links, path)
			return nil
		}
		found = append(found, path)
		return nil
	})
	sort.Strings(found)
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
	for _, path := range paths {
		src, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		fp := FilePlan{Path: path}
		for _, line := range envfile.Parse(src).Assignments() {
			d := classify.Classify(line.Key, line.Value)
			projected := classify.Project(line.Value, d)
			refs := make([]string, 0, len(d.Spans))
			for _, s := range d.Spans {
				refs = append(refs, s.Ref)
			}
			fp.Entries = append(fp.Entries, Entry{
				Key:       line.Key,
				Decision:  d,
				Projected: projected,
				Refs:      refs,
			})
			switch d.Class {
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

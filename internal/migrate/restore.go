package migrate

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/ByteFinch-Technologies/secretveil/internal/envfile"
	"github.com/ByteFinch-Technologies/secretveil/internal/handle"
	"github.com/ByteFinch-Technologies/secretveil/internal/npmrc"
)

// shapeMark is how a shape comment starts. Only a comment that init wrote is
// removed by restore.
const shapeMark = "# sv:"

// Reader is the part of a store that restore needs.
type Reader interface {
	Get(ctx context.Context, ref string) (string, error)
}

// RestoreResult reports what restore did.
type RestoreResult struct {
	// Files names every file that changed.
	Files []string `json:"files"`
	// Handles counts the handles that were replaced.
	Handles int `json:"handles"`
	// Missing names every reference that the store does not hold. A file that
	// needs one of these is left alone.
	Missing []string `json:"missing,omitempty"`
}

// Restore puts the plaintext values back in the .env and .npmrc files.
//
// It is the exact inverse of Apply. It reads each reference, asks the store for
// the value, and writes the value in place of the reference. It needs no backup,
// because the file with the references and the store together hold everything
// the original file held.
//
// It stops before it writes anything if the store cannot supply every value.
// A file that is half restored is worse than a file that is not restored.
func Restore(ctx context.Context, st Reader, root string, dryRun bool) (*RestoreResult, error) {
	res := &RestoreResult{}

	var jobs []restoreJob
	values := map[string]string{}
	missing := map[string]bool{}

	// lookup asks the store once for each reference and remembers the answer.
	// A reference the store cannot supply is recorded, and the whole restore
	// stops later, before any file is written.
	lookup := func(ref string) (string, bool) {
		if missing[ref] {
			return "", false
		}
		if v, ok := values[ref]; ok {
			return v, true
		}
		v, err := st.Get(ctx, ref)
		if err != nil {
			missing[ref] = true
			return "", false
		}
		values[ref] = v
		return v, true
	}

	envJobs, err := restoreDotenv(root, res, lookup)
	if err != nil {
		return nil, err
	}
	jobs = append(jobs, envJobs...)

	npmJobs, err := restoreNpmrc(root, res, lookup)
	if err != nil {
		return nil, err
	}
	jobs = append(jobs, npmJobs...)

	for ref := range missing {
		res.Missing = append(res.Missing, ref)
	}
	sort.Strings(res.Missing)
	if len(res.Missing) > 0 {
		return res, fmt.Errorf("the store holds no value for %v, so nothing was changed", res.Missing)
	}
	if dryRun {
		for _, j := range jobs {
			res.Files = append(res.Files, j.path)
		}
		return res, nil
	}

	// Every write is atomic, and an earlier write is undone if a later one
	// fails, so the set of files stays consistent.
	var done []restoreJob
	for _, j := range jobs {
		old, err := os.ReadFile(j.path)
		if err != nil {
			return res, undoRestore(done, err)
		}
		if err := writeAtomic(j.path, j.body, j.mode); err != nil {
			return res, undoRestore(done, err)
		}
		done = append(done, restoreJob{path: j.path, body: old, mode: j.mode})
		res.Files = append(res.Files, j.path)
	}
	return res, nil
}

// restoreDotenv builds the work for every .env file. It writes nothing.
func restoreDotenv(root string, res *RestoreResult, lookup func(string) (string, bool)) ([]restoreJob, error) {
	paths, err := Discover(root)
	if err != nil {
		return nil, err
	}
	var jobs []restoreJob
	for _, path := range paths {
		src, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		parsed := envfile.Parse(src)
		changed := false

		for _, line := range parsed.Assignments() {
			if !handle.Contains(line.Value) {
				continue
			}
			out, _ := handle.Resolve(line.Value, lookup)
			if out == line.Value {
				continue
			}
			// The count has to happen before the write. Set changes the same
			// line that this loop holds, so a count after it reads the new
			// value twice and always gives zero.
			replaced := strings.Count(line.Value, handle.Scheme) - strings.Count(out, handle.Scheme)
			parsed.Set(line.Key, out)
			// The shape comment described the handle. The value is back, so
			// the comment has no meaning any more. A comment that the
			// developer wrote stays, because it is not ours to remove.
			if strings.Contains(line.Inline, shapeMark) {
				parsed.SetInline(line.Key, "")
			}
			res.Handles += replaced
			changed = true
		}
		if changed {
			jobs = append(jobs, restoreJob{path: path, body: parsed.Bytes(), mode: fileMode(path)})
		}
	}
	return jobs, nil
}

// restoreNpmrc builds the work for every .npmrc file. It writes nothing.
//
// Only a value that is one whole marker is put back. A value that holds a
// marker among other text was not written by this tool, and npm expands the
// variable itself at read time, so there is nothing here to undo.
func restoreNpmrc(root string, res *RestoreResult, lookup func(string) (string, bool)) ([]restoreJob, error) {
	paths, err := DiscoverNpmrc(root)
	if err != nil {
		return nil, err
	}
	var jobs []restoreJob
	for _, path := range paths {
		src, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		parsed := npmrc.Parse(src)
		changed := false

		for i := range parsed.Lines {
			line := &parsed.Lines[i]
			refs := npmrc.Markers(line.Value)
			if len(refs) != 1 || line.Value != npmrc.Marker(refs[0]) {
				continue
			}
			v, ok := lookup(refs[0])
			if !ok {
				continue
			}
			if !line.Set(v) {
				return nil, fmt.Errorf("%s: the value of %s cannot go back in this file, "+
					"because npm would read it differently from the way it is stored", path, line.Key)
			}
			res.Handles++
			changed = true
		}
		if changed {
			jobs = append(jobs, restoreJob{path: path, body: parsed.Bytes(), mode: fileMode(path)})
		}
	}
	return jobs, nil
}

// restoreJob is one file to write, and the bytes to write into it.
type restoreJob struct {
	path string
	body []byte
	mode os.FileMode
}

// undoRestore puts back the files that were already written.
func undoRestore(done []restoreJob, cause error) error {
	for i := len(done) - 1; i >= 0; i-- {
		if err := writeAtomic(done[i].path, done[i].body, done[i].mode); err != nil {
			return fmt.Errorf("the restore failed and %s could not be put back: %v. The first fault was: %w",
				done[i].path, err, cause)
		}
	}
	return cause
}

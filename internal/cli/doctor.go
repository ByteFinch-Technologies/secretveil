package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/ByteFinch-Technologies/secretveil/internal/classify"
	"github.com/ByteFinch-Technologies/secretveil/internal/coverage"
	"github.com/ByteFinch-Technologies/secretveil/internal/detect"
	"github.com/ByteFinch-Technologies/secretveil/internal/envfile"
	"github.com/ByteFinch-Technologies/secretveil/internal/handle"
	"github.com/ByteFinch-Technologies/secretveil/internal/migrate"
	"github.com/ByteFinch-Technologies/secretveil/internal/policy"
	"github.com/ByteFinch-Technologies/secretveil/internal/project"
	"github.com/ByteFinch-Technologies/secretveil/internal/store/agefile"
	"github.com/spf13/cobra"
)

// level is how bad one finding is.
type level int

const (
	levelOK level = iota
	levelNote
	levelWarn
	levelBad
)

func (l level) mark() string {
	switch l {
	case levelOK:
		return "ok  "
	case levelNote:
		return "note"
	case levelWarn:
		return "warn"
	default:
		return "BAD "
	}
}

// scopeNote states the limit of the report. It prints under every summary,
// including a clean one, because a developer reads the last line and stops.
const scopeNote = "These checks read the .env files, the store and a short list of known credential\n" +
	"files. A secret in any other kind of file is not covered and was not looked at."

// finding is one line of the report.
type finding struct {
	level level
	title string
	// detail is the advice. It is what the developer does next.
	detail []string
}

func newDoctor() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "doctor [path]",
		Short: "Check the setup of this project and say what to fix",
		Long: `doctor looks at the project and reports anything that would surprise you
later. It writes nothing and it changes nothing.

It checks that the store opens on this machine, that every handle in your .env
files has a value behind it, that no plaintext secret is left in a file, that
.gitignore covers the store, and that the policy file loads.

It also names a credential in a file that secretveil does not rewrite, such as
.npmrc or .netrc. It cannot protect those files, and it says so rather than
report a clean project.

The exit code is 0 when nothing is wrong, and 1 when a check found something
that puts a secret at risk. A note or a warning does not change the exit code.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root, err := rootFrom(args)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Project: %s\n\n", root)

			found := runChecks(ctxOrBackground(cmd.Context()), root)
			worst := levelOK
			for _, f := range found {
				if f.level > worst {
					worst = f.level
				}
				fmt.Fprintf(out, "  [%s] %s\n", f.level.mark(), f.title)
				for _, d := range f.detail {
					fmt.Fprintf(out, "         %s\n", d)
				}
			}

			// Each line below says what the checks found. None of them says
			// that the project holds no secret, because doctor reads the .env
			// files, the store and a short list of known credential files, and
			// it does not read the rest of the repository. A summary that
			// claimed more than that would tell the developer to stop looking.
			switch worst {
			case levelOK:
				fmt.Fprintln(out, "\nEvery check passed.")
			case levelBad:
				fmt.Fprintln(out, "\nSomething here puts a secret at risk. Fix the BAD lines first.")
				fmt.Fprintln(out, scopeNote)
				return &exitError{code: 1}
			default:
				fmt.Fprintln(out, "\nNo check found a secret at risk. Read the lines above.")
			}
			fmt.Fprintln(out, scopeNote)
			return nil
		},
	}
	return cmd
}

// runChecks gathers every finding, in the order a developer would want to read
// them: the setup first, then the secrets, then the housekeeping.
func runChecks(ctx context.Context, root string) []finding {
	var found []finding
	add := func(f finding) { found = append(found, f) }

	add(checkCaller())
	st, file := openStore(root)
	add(checkStore(root, file))

	refs, err := file.List(ctx)
	if err != nil {
		// The store did not open, so every check below it would only repeat
		// the same failure.
		add(finding{levelWarn, "the checks below need the store, and it did not open", nil})
		return found
	}
	sort.Strings(refs)

	plan, perr := migrate.BuildPlan(root)
	if perr != nil {
		add(finding{levelWarn, "the .env files could not be read: " + perr.Error(), nil})
		return found
	}

	add(checkPlaintext(plan))
	add(checkUncovered(root))
	used := handlesInFiles(root)
	add(checkDangling(ctx, st, used))
	add(checkOrphans(refs, used))
	add(checkLinks(root, plan))
	add(checkIgnore(root))
	add(checkBackup(root))
	add(checkPolicy(root))
	return found
}

// checkCaller reports what secretveil thinks started it. This is the first
// question a developer asks after a refusal they did not expect.
func checkCaller() finding {
	who := detect.Detect()
	f := finding{levelOK, fmt.Sprintf("this caller looks like a %s, because %s", who.Caller, who.Reason), nil}
	if who.Caller == detect.Agent {
		f.level = levelNote
		f.detail = []string{
			"An agent may not start a shell here. Set " + detect.EnvOverride + "=human if that is wrong.",
		}
	}
	return f
}

func checkStore(root string, file *agefile.Store) finding {
	path := filepath.Join(project.Dir, agefile.FileName)
	if _, err := os.Stat(file.Path()); err != nil {
		return finding{levelNote, "there is no store yet at " + path, []string{
			"Run \"secretveil init\" to move the secrets of this project into one.",
		}}
	}
	if !file.Available() {
		return finding{levelBad, "the store is here, and this machine cannot open it", []string{
			"This machine has no keyring, and " + agefile.EnvPassphrase + " is not set.",
			"Set " + agefile.EnvPassphrase + ", or move the key into the keyring of this machine.",
		}}
	}
	if _, err := file.List(context.Background()); err != nil {
		return finding{levelBad, "the store did not open: " + err.Error(), []string{
			"The key for this project may belong to another machine or another user.",
		}}
	}
	return finding{levelOK, "the store opens on this machine", nil}
}

// checkPlaintext is the check that matters most. A value that an agent can read
// makes the rest of the tool beside the point.
func checkPlaintext(plan *migrate.Plan) finding {
	var where []string
	for _, f := range plan.Files {
		for _, e := range f.Entries {
			if e.Decision.Class != classify.Open {
				where = append(where, fmt.Sprintf("%s holds the value of %s", relTo(plan.Root, f.Path), e.Key))
			}
		}
	}
	if len(where) == 0 {
		return finding{levelOK, "no .env file holds a plaintext secret", nil}
	}
	if len(where) > 8 {
		rest := len(where) - 8
		where = append(where[:8], fmt.Sprintf("and %d more", rest))
	}
	return finding{levelBad,
		fmt.Sprintf("%d plaintext secrets are still in the files an agent reads", len(where)),
		append(where, "Run \"secretveil init\" to move them into the store."),
	}
}

// checkUncovered names a credential that secretveil does not put a handle into.
//
// This check exists because the report used to end with "nothing is at risk"
// while an npm token sat in .npmrc in the same directory. doctor had never
// opened that file. The honest report names the file and says plainly that the
// tool does not cover it.
//
// The level is a warning and not a fault, so the exit code stays 0. A project
// can hold a .netrc that nothing can fix, and a check that fails forever is a
// check that developers learn to ignore.
func checkUncovered(root string) finding {
	found, err := coverage.Scan(root, migrate.SkipDir, nil)
	if err != nil {
		return finding{levelNote, "the search for other credential files did not finish: " + err.Error(), nil}
	}
	if len(found) == 0 {
		return finding{levelOK,
			"no other known credential file holds a value here", []string{
				"Checked for: " + strings.Join(coverage.Kinds(), ", ") + ".",
			}}
	}
	detail := make([]string, 0, len(found)*2+1)
	for _, f := range found {
		where := relTo(root, f.Path)
		// The kind is only worth printing when it does not repeat the name of
		// the file. ".npmrc (.npmrc)" tells the reader nothing.
		if filepath.Base(f.Path) != f.Kind {
			where += " (" + f.Kind + ")"
		}
		detail = append(detail, fmt.Sprintf("%s, line %s: %s", where, joinInts(f.Lines), f.Advice))
	}
	detail = append(detail,
		"secretveil does not rewrite these files, so init and doctor cannot protect them.")
	return finding{levelWarn,
		fmt.Sprintf("%d file(s) hold a credential that secretveil does not cover", len(found)),
		detail}
}

// joinInts renders a list of line numbers.
func joinInts(list []int) string {
	parts := make([]string, 0, len(list))
	for _, n := range list {
		parts = append(parts, strconv.Itoa(n))
	}
	return strings.Join(parts, ", ")
}

// checkDangling finds a handle with no value behind it. The program would start
// and then fail somewhere in the middle, which is the worst time to find out.
func checkDangling(ctx context.Context, st interface {
	Get(context.Context, string) (string, error)
}, used map[string][]string,
) finding {
	if len(used) == 0 {
		return finding{levelOK, "no .env file uses a handle yet", nil}
	}
	var missing []string
	for ref := range used {
		if _, err := st.Get(ctx, ref); err != nil {
			missing = append(missing, ref)
		}
	}
	if len(missing) == 0 {
		return finding{levelOK,
			fmt.Sprintf("all %d handles in the .env files have a value behind them", len(used)), nil}
	}
	sort.Strings(missing)

	detail := make([]string, 0, len(missing)+1)
	for _, ref := range missing {
		detail = append(detail, fmt.Sprintf("%s, used in %s", ref, strings.Join(used[ref], ", ")))
	}
	detail = append(detail, "Run \"secretveil set <ref>\" for each one.")
	return finding{levelBad, fmt.Sprintf("%d handles have no value in the store", len(missing)), detail}
}

// checkOrphans finds a value nobody uses. This is not a risk, it is tidiness,
// so it is only a note.
func checkOrphans(refs []string, used map[string][]string) finding {
	if len(refs) == 0 {
		return finding{levelOK, "the store is empty", nil}
	}
	var spare []string
	for _, ref := range refs {
		if _, ok := used[ref]; !ok {
			spare = append(spare, ref)
		}
	}
	if len(spare) == 0 {
		return finding{levelOK,
			fmt.Sprintf("all %d values in the store are used by a file", len(refs)), nil}
	}
	return finding{levelNote,
		fmt.Sprintf("%d values in the store are not used by any .env file", len(spare)),
		[]string{
			strings.Join(spare, ", "),
			"This is not a risk. Run \"secretveil rm <ref>\" if you no longer need one.",
		},
	}
}

func checkLinks(root string, plan *migrate.Plan) finding {
	if len(plan.Links) == 0 {
		return finding{levelOK, "no .env file is a symbolic link", nil}
	}
	detail := make([]string, 0, len(plan.Links)+1)
	for _, l := range plan.Links {
		detail = append(detail, relTo(root, l))
	}
	detail = append(detail, "secretveil never follows one, so these files are not covered. Deal with each by hand.")
	return finding{levelWarn, fmt.Sprintf("%d .env files are symbolic links", len(plan.Links)), detail}
}

// checkIgnore looks for the one mistake that undoes everything: the encrypted
// store committed to the repository.
func checkIgnore(root string) finding {
	dir := filepath.Join(root, project.Dir)
	if _, err := os.Stat(dir); err != nil {
		return finding{levelOK, "there is nothing to keep out of the repository yet", nil}
	}
	body, err := os.ReadFile(filepath.Join(root, ".gitignore"))
	if err != nil {
		if _, gerr := os.Stat(filepath.Join(root, ".git")); gerr != nil {
			return finding{levelOK, "this is not a git repository, so there is nothing to ignore", nil}
		}
		return finding{levelWarn, "this repository has no .gitignore", []string{
			"Add a line that reads " + project.Dir + "/ so the encrypted store stays off the remote.",
		}}
	}
	for _, line := range strings.Split(string(body), "\n") {
		switch strings.TrimSpace(line) {
		case project.Dir + "/", project.Dir, project.Dir + "/*":
			return finding{levelOK, ".gitignore covers " + project.Dir + "/", nil}
		}
	}
	return finding{levelWarn, ".gitignore does not cover " + project.Dir + "/", []string{
		"The encrypted store is safe to lose, but it does not belong on a remote.",
		"Add a line that reads " + project.Dir + "/",
	}}
}

// checkBackup looks for the plaintext copy that init makes and then deletes. A
// copy left behind holds every secret in the clear.
func checkBackup(root string) finding {
	dir := filepath.Join(root, migrate.BackupRoot)
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 {
		return finding{levelOK, "no plaintext backup is left on disk", nil}
	}
	return finding{levelBad, fmt.Sprintf("%s holds a plaintext copy of your secrets", migrate.BackupRoot), []string{
		"init makes this copy and deletes it when it finishes. One that is still here was kept on purpose.",
		"Remove it when you are sure the migration worked: rm -rf " + dir,
	}}
}

func checkPolicy(root string) finding {
	path := filepath.Join(root, project.Dir, policy.FileName)
	if _, err := os.Stat(path); err != nil {
		return finding{levelNote, "this project has no policy file, so the default rules apply", nil}
	}
	p, err := policy.Load(root)
	if err != nil {
		return finding{levelBad, "the policy file did not load", []string{
			err.Error(),
			"Every command that an agent runs fails until this is fixed.",
		}}
	}
	if !p.Agent.Enforce {
		return finding{levelWarn, "the command rules are turned off in the policy file", []string{
			"An agent may start a shell here. The output filter still runs.",
		}}
	}
	return finding{levelOK, "the policy file loads and the command rules are on", nil}
}

// handlesInFiles maps every reference in the .env files to the files that use
// it.
func handlesInFiles(root string) map[string][]string {
	used := map[string][]string{}
	paths, err := migrate.Discover(root)
	if err != nil {
		return used
	}
	for _, path := range paths {
		src, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		name := relTo(root, path)
		for _, line := range envfile.Parse(src).Assignments() {
			for _, ref := range handle.Refs(line.Value) {
				if !containsString(used[ref], name) {
					used[ref] = append(used[ref], name)
				}
			}
		}
	}
	return used
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func relTo(root, path string) string {
	if rel, err := filepath.Rel(root, path); err == nil {
		return rel
	}
	return path
}

package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/ByteFinch-Technologies/secretveil/internal/coverage"
	"github.com/ByteFinch-Technologies/secretveil/internal/detect"
	"github.com/ByteFinch-Technologies/secretveil/internal/envfile"
	"github.com/ByteFinch-Technologies/secretveil/internal/handle"
	"github.com/ByteFinch-Technologies/secretveil/internal/migrate"
	"github.com/ByteFinch-Technologies/secretveil/internal/npmrc"
	"github.com/ByteFinch-Technologies/secretveil/internal/policy"
	"github.com/ByteFinch-Technologies/secretveil/internal/project"
	"github.com/ByteFinch-Technologies/secretveil/internal/runtime"
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
const scopeNote = "One check searches every file under this project for a value that the store\n" +
	"already holds. Every other check reads the .env files, the .npmrc files, the\n" +
	"store and a short list of known credential files. A secret that is in none of\n" +
	"those, and that the store has never held, was not looked at."

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

It checks that the store opens on this machine, that every reference in your
.env and .npmrc files has a value behind it, that no file still holds a value
that the store already holds, that .gitignore covers the store, and that the
policy file loads.

It also names a value that stayed in the file and that reads like a credential
even though no rule recognised it. That one is a question for you, not a fault,
so it never changes the exit code.

It also names a credential in a file that secretveil does not rewrite, such as
.netrc, .yarnrc.yml or bunfig.toml. It cannot protect those files, and it says so
rather than report a clean project.

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
	// The handles come first, because the advice for a missing store depends
	// on them. A project whose files already hold handles does not wait for
	// init.
	used := handlesInFiles(root)
	add(checkStore(file, used))

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

	for _, f := range checkPlaintext(ctx, root, file, refs, plan) {
		add(f)
	}
	add(checkUnrecognised(root, plan))
	add(checkUncovered(root, plan))
	add(checkUnread(root))
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

func checkStore(file *agefile.Store, used map[string][]string) finding {
	path := filepath.Join(project.Dir, agefile.FileName)
	if _, err := os.Stat(file.Path()); err != nil {
		// A project whose files already hold handles does not wait for init.
		// The store and its key belong to the person who ran init, and they
		// travel out of band. A second init here would only write a second
		// empty store, and it would not give this machine the values.
		if len(used) > 0 {
			return finding{levelBad, "the files of this project hold handles, and there is no store at " + path, []string{
				"Get " + path + " and its key from the person who ran \"secretveil init\".",
				"Or run \"secretveil set <ref>\" for each handle, to write the values again on this machine.",
			}}
		}
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

// checkPlaintext is the check that matters most. A value that an agent can
// read makes the rest of the tool beside the point.
//
// It reads the values out of the store and then searches the files for them.
// It does not ask the classifier. The classifier is the thing that can be
// wrong, so a check that read its answer reported a clean project for exactly
// the one fault it existed to find: a value no rule recognised was called open,
// and "open" was then read as "this is not a secret". The same circle was found
// once before in checkUncovered.
//
// The search returns two kinds of place, and they are not the same fault. A
// value inside a file that secretveil rewrites is a fault of this tool, and it
// is BAD. A value in some other file is a fault of the project that this tool
// cannot fix, and it is a warning, so that a project which keeps a fixture file
// does not fail this check forever.
func checkPlaintext(ctx context.Context, root string, file *agefile.Store,
	refs []string, plan *migrate.Plan) []finding {

	if len(refs) == 0 {
		return []finding{{levelNote, "the store holds no value, so there is nothing to search for", nil}}
	}
	secrets := make(map[string]string, len(refs))
	for _, ref := range refs {
		v, err := file.Get(ctx, ref)
		if err != nil {
			return []finding{{levelWarn,
				"the search for plaintext did not run, because " + ref + " did not open: " + err.Error(), nil}}
		}
		secrets[ref] = v
	}

	found, err := migrate.SearchTree(root, secrets)
	if err != nil {
		return []finding{{levelWarn, "the search for plaintext did not finish: " + err.Error(), nil}}
	}

	covered := map[string]bool{}
	for _, f := range plan.Files {
		covered[f.Path] = true
	}
	var inCovered, elsewhere []string
	for _, l := range found {
		line := fmt.Sprintf("%s, line %d: this holds the value behind %s",
			relTo(root, l.Path), l.Line, handle.Scheme+l.Ref)
		if covered[l.Path] {
			inCovered = append(inCovered, line)
		} else {
			elsewhere = append(elsewhere, line)
		}
	}

	out := make([]finding, 0, 2)
	if len(inCovered) == 0 {
		out = append(out, finding{levelOK, "no file that secretveil rewrites holds a value from the store", nil})
	} else {
		out = append(out, finding{levelBad,
			fmt.Sprintf("%d plaintext secret(s) are still in the files an agent reads", len(inCovered)),
			append(trimList(inCovered), "Run \"secretveil init\" to move them into the store.")})
	}
	if len(elsewhere) > 0 {
		out = append(out, finding{levelWarn,
			fmt.Sprintf("%d other file(s) hold a value that is also in the store", len(elsewhere)),
			append(trimList(elsewhere),
				"secretveil does not rewrite these files. Remove the value by hand, or rotate it.")})
	}
	return out
}

// checkUnrecognised reports a value that stayed in the file and that still
// reads like a credential.
//
// The level is a warning and not a fault, so the exit code stays 0. This check
// reports a doubt and not a finding, and a doubt that fails a build is a doubt
// that somebody switches off. It is also the one check whose right answer can
// be "no", which is why it never asks the developer to prove anything.
func checkUnrecognised(root string, plan *migrate.Plan) finding {
	list := plan.Unrecognised()
	if len(list) == 0 {
		return finding{levelOK, "every open value is one that a rule recognised", nil}
	}
	detail := make([]string, 0, len(list)+2)
	for _, u := range list {
		detail = append(detail, fmt.Sprintf("%s, %s: %s", relTo(root, u.Path), u.Key, u.Reason))
	}
	detail = trimList(detail)
	detail = append(detail,
		"An agent reads each of these in full, because no rule knows what they are.",
		"If one is a secret, rename the variable so that its name says so (for example "+
			list[0].Key+"_SECRET), then run \"secretveil init\" again.")
	return finding{levelWarn,
		fmt.Sprintf("%d value(s) stay open and no rule knows what they are", len(list)),
		detail}
}

// maxListed is how many places one finding names. A report that prints two
// hundred lines is a report that nobody reads to the end.
const maxListed = 8

// trimList shortens a list and says how much it took away. It never hides the
// count, because the count is in the title of the finding.
func trimList(lines []string) []string {
	if len(lines) <= maxListed {
		return lines
	}
	rest := len(lines) - maxListed
	return append(lines[:maxListed:maxListed], fmt.Sprintf("and %d more", rest))
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
// checkUnread reports a .env file that holds a handle but that "run" does not
// read on its own.
//
// This check exists because the report was wrong without it. A project with a
// handle in .env.development passed every other check, because the value was in
// the store and the file was rewritten. Nothing asked whether anything would
// ever read that file. The developer got "Every check passed" and a program
// that received the text "sv://stripe_dev_key" as its key.
//
// The advice is a whole command line, and not a rule to work out. The load
// order of these files is the part a developer gets wrong.
func checkUnread(root string) finding {
	extra, err := runtime.Unread(root)
	if err != nil {
		return finding{levelNote, "the .env files could not be listed: " + err.Error(), nil}
	}
	if len(extra) == 0 {
		return finding{levelOK, "run reads every .env file that holds a handle", nil}
	}

	detail := make([]string, 0, len(extra)+3)
	for _, name := range extra {
		detail = append(detail, name+": init rewrote this file, but run does not read it")
	}
	detail = append(detail,
		"Your framework reads the file itself and gives the program the handle text.",
		"Name the files you want, in load order. A later file wins over an earlier one:",
		"  "+runtime.RunLine(runtime.LoadOrder(root, extra)))
	return finding{levelWarn,
		fmt.Sprintf("%d .env file(s) hold a handle that run does not resolve", len(extra)),
		detail}
}

func checkUncovered(root string, plan *migrate.Plan) finding {
	found, err := coverage.Scan(root, migrate.SkipDir, plannedLine(plan))
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
		"secretveil does not rewrite these lines, so init and doctor cannot protect them.")
	return finding{levelWarn,
		fmt.Sprintf("%d file(s) hold a credential that secretveil does not cover", len(found)),
		detail}
}

// plannedLine reports whether the migration already handles one line of one
// file. The line that "secretveil init" rewrites belongs to the plaintext check,
// and the line it cannot rewrite belongs to the check above. A line that both
// checks named, or that neither named, would be a fault in the report.
func plannedLine(plan *migrate.Plan) func(path string, line int) bool {
	if plan == nil {
		return nil
	}
	planned := map[string]map[int]bool{}
	for _, f := range plan.Files {
		// Only a file whose record index is also its physical line belongs in
		// this map. A .env record with a multi-line quoted value covers more
		// than one physical line, so its index would mark the wrong line here.
		if f.Kind != migrate.KindNpmrc {
			continue
		}
		for _, e := range f.Entries {
			if e.Line == 0 {
				continue
			}
			if planned[f.Path] == nil {
				planned[f.Path] = map[int]bool{}
			}
			planned[f.Path][e.Line] = true
		}
	}
	return func(path string, line int) bool { return planned[path][line] }
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
		return finding{levelOK, "no file uses a reference yet", nil}
	}
	var missing []string
	for ref := range used {
		if _, err := st.Get(ctx, ref); err != nil {
			missing = append(missing, ref)
		}
	}
	if len(missing) == 0 {
		return finding{levelOK,
			fmt.Sprintf("all %d references in the project files have a value behind them", len(used)), nil}
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
		fmt.Sprintf("%d values in the store are not used by any file", len(spare)),
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

// handlesInFiles maps every reference in the project files to the files that
// use it.
//
// The .npmrc files are read as well as the .env files. Without them, doctor
// called every registry token an orphan and told the developer to remove it.
// That advice would have broken npm and lost the token.
func handlesInFiles(root string) map[string][]string {
	used := map[string][]string{}
	mark := func(path, ref string) {
		name := relTo(root, path)
		if !containsString(used[ref], name) {
			used[ref] = append(used[ref], name)
		}
	}

	if paths, err := migrate.Discover(root); err == nil {
		for _, path := range paths {
			src, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			for _, line := range envfile.Parse(src).Assignments() {
				for _, ref := range handle.Refs(line.Value) {
					mark(path, ref)
				}
			}
		}
	}

	if paths, err := migrate.DiscoverNpmrc(root); err == nil {
		for _, path := range paths {
			src, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			for _, ref := range npmrc.Markers(string(src)) {
				mark(path, ref)
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

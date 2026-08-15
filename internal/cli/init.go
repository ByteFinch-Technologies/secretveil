package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ByteFinch-Technologies/secretveil/internal/audit"
	"github.com/ByteFinch-Technologies/secretveil/internal/detect"
	"github.com/ByteFinch-Technologies/secretveil/internal/migrate"
	"github.com/ByteFinch-Technologies/secretveil/internal/policy"
	"github.com/ByteFinch-Technologies/secretveil/internal/project"
	"github.com/ByteFinch-Technologies/secretveil/internal/store/agefile"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func newInit() *cobra.Command {
	var dryRun, yes, noIgnore, keepBackup, verbose bool

	cmd := &cobra.Command{
		Use:   "init [path]",
		Short: "Move every secret into the store and put a handle in its place",
		Long: `init changes every .env file in the project. It reads each value, decides
whether the value is a secret, writes the secret into the encrypted store, and
puts a handle such as sv://api_key in the file.

After init, the .env file holds no secret. Any AI tool may read it, and no
integration with that tool is needed. Your program still sees the real value,
because "secretveil run" puts it back in the environment of the child process.

init is safe to stop. Each step can be undone, and a failure in any step puts
every file back the way it was. Run "secretveil plan" first to see what init
would do.

To undo init later, run "secretveil restore". It gives back the original file,
byte for byte.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root, err := rootFrom(args)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			errOut := cmd.ErrOrStderr()

			plan, err := migrate.BuildPlan(root)
			if err != nil {
				return err
			}
			if plan.Counts.Partial+plan.Counts.Veiled == 0 {
				fmt.Fprintf(out, "There is no secret to move under %s.\n", root)
				if plan.Counts.Open > 0 {
					fmt.Fprintf(out, "%d variables look open, so they stay as they are.\n", plan.Counts.Open)
				}
				for _, l := range plan.Links {
					fmt.Fprintf(out, "%s is a symbolic link, and secretveil never follows one.\n", l)
				}
				return nil
			}

			writeTable(out, plan, root)
			if dryRun {
				fmt.Fprintln(out, "\nThis was a dry run. Nothing changed.")
				return nil
			}
			question := fmt.Sprintf("Move %d secrets into the store and rewrite the files above?",
				plan.Counts.Partial+plan.Counts.Veiled)
			if err := confirm(cmd.InOrStdin(), out, yes, question); err != nil {
				return err
			}

			if err := ensureKeyEntry(root); err != nil {
				return err
			}
			_, file := openStore(root)
			if !file.Available() {
				return fmt.Errorf(
					"this machine has no keyring and no passphrase, so there is nowhere to put the secrets. Set %s and run init again",
					agefile.EnvPassphrase)
			}

			opt := migrate.Options{
				Root:       root,
				SkipIgnore: noIgnore,
				KeepBackup: keepBackup,
			}
			if verbose {
				opt.Log = func(p migrate.Phase, msg string) {
					fmt.Fprintf(errOut, "  [%d/%d] %s\n", int(p), int(migrate.PhaseDone), msg)
				}
			}

			res, err := migrate.Apply(ctxOrBackground(cmd.Context()), file, opt)
			if err != nil {
				return err
			}
			if err := writeSamplePolicy(root); err != nil {
				return err
			}
			who := detect.Detect()
			_ = audit.New(root).Write(audit.Record{
				Event:  audit.EventInit,
				Caller: who.Caller.String(),
				Reason: who.Reason,
				Refs:   res.Refs,
			})
			reportInit(out, errOut, root, res, keepBackup)
			return nil
		},
	}

	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show the plan and write nothing")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "do not ask for confirmation")
	cmd.Flags().BoolVar(&noIgnore, "no-ignore", false, "do not add .secretveil/ to .gitignore")
	cmd.Flags().BoolVar(&keepBackup, "keep-backup", false,
		"leave the plaintext backup on disk. This keeps your secrets in the clear, so do not use it")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "print one line for each step")
	return cmd
}

// ensureKeyEntry gives the project a stable keyring entry name.
//
// The name is written only for a project that has no store yet. A project that
// already holds an encrypted file keeps whatever name opened that file, because
// a new name would point at a new key and lock the developer out of their own
// secrets.
func ensureKeyEntry(root string) error {
	dir := filepath.Join(root, project.Dir)
	if _, err := os.Stat(filepath.Join(dir, project.KeyRefFile)); err == nil {
		return nil
	}
	if _, err := os.Stat(filepath.Join(dir, agefile.FileName)); err == nil {
		return nil
	}
	entry, err := project.NewKeyEntry()
	if err != nil {
		return err
	}
	return project.WriteKeyEntry(root, entry)
}

// writeSamplePolicy puts a documented policy file in the project.
//
// It never replaces a file that is already there, because the developer may
// have changed it. The sample explains every rule, because a security setting
// that nobody understands gets turned off.
func writeSamplePolicy(root string) error {
	path := filepath.Join(root, project.Dir, policy.FileName)
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	return os.WriteFile(path, []byte(policy.Sample), 0o600)
}

// errRefused is the answer of a developer who said no at the prompt.
var errRefused = errors.New("init stopped, and nothing changed")

// confirm asks before the first write.
//
// A command that has no terminal and no --yes flag stops. init rewrites files
// in the project, and a tool that runs it without a human behind it must say so
// with the flag.
func confirm(in io.Reader, out io.Writer, yes bool, question string) error {
	if yes {
		return nil
	}
	f, ok := in.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return errors.New("this command needs an answer, but there is no terminal here. Add --yes to run it without one")
	}
	fmt.Fprintf(out, "\n%s [y/N] ", question)
	line, err := bufio.NewReader(f).ReadString('\n')
	if err != nil && line == "" {
		return errRefused
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return nil
	}
	return errRefused
}

// reportInit prints what changed. It never prints a value.
func reportInit(out, errOut io.Writer, root string, res *migrate.Result, keptBackup bool) {
	fmt.Fprintf(out, "\nMoved %d secrets into %s.\n",
		len(res.Refs), filepath.Join(project.Dir, agefile.FileName))
	for _, p := range res.Rewritten {
		if rel, err := filepath.Rel(root, p); err == nil {
			p = rel
		}
		fmt.Fprintf(out, "  rewrote %s\n", p)
	}

	if len(res.Renamed) > 0 {
		fmt.Fprintf(out, "\n%d names collided, so init renamed them:\n", len(res.Renamed))
		for from, to := range res.Renamed {
			fmt.Fprintf(out, "  %s -> %s\n", from, to)
		}
	}

	if len(res.Leftover) > 0 {
		fmt.Fprintf(errOut, "\nWarning: %d other files still hold one of these secrets in plaintext.\n",
			len(res.Leftover))
		fmt.Fprintln(errOut, "init did not touch them, because they are not .env files. Deal with each one:")
		for _, l := range res.Leftover {
			p := l.Path
			if rel, err := filepath.Rel(root, p); err == nil {
				p = rel
			}
			fmt.Fprintf(errOut, "  %s line %d holds the value of %s\n", p, l.Line, l.Ref)
		}
	}

	if keptBackup && res.Backup != "" {
		fmt.Fprintf(errOut, "\nWarning: the plaintext backup is still at %s. Remove it when you are done.\n",
			res.Backup)
	}

	fmt.Fprintln(out, "\nNext, put secretveil in front of the command that needs the values:")
	fmt.Fprintln(out, "  secretveil run -- npm run dev")
}

// ctxOrBackground is here so a command with no context still works in a test.
func ctxOrBackground(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ByteFinch-Technologies/secretveil/internal/audit"
	"github.com/ByteFinch-Technologies/secretveil/internal/detect"
	"github.com/ByteFinch-Technologies/secretveil/internal/policy"
	"github.com/ByteFinch-Technologies/secretveil/internal/project"
	"github.com/ByteFinch-Technologies/secretveil/internal/runtime"
	"github.com/spf13/cobra"
)

// exitError carries an exit code out of a command without a message. The root
// command turns it into the exit code of secretveil itself.
type exitError struct{ code int }

func (e *exitError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

func newRun() *cobra.Command {
	var (
		files     []string
		dir       string
		noPTY     bool
		forcePTY  bool
		quiet     bool
		allowMiss bool
		idle      time.Duration
	)

	cmd := &cobra.Command{
		Use:   "run -- <command> [args...]",
		Short: "Run a program with the real secrets, and filter them out of its output",
		Long: `run does three things.

It reads the .env files, replaces every sv:// handle with the real value, and
puts the result in the environment of the program. Your framework then loads
the variables the way it always did, because a value in the environment always
wins over a value in a file.

It gives the program a terminal, so colour, progress bars and a password
prompt all still work.

It reads every byte the program prints and removes every secret from it. A
secret that leaks into a stack trace or a debug log never reaches the screen.`,
		Example: `  secretveil run -- npm run dev
  secretveil run -- python manage.py runserver
  secretveil run --no-pty -- go test ./...`,
		Args:                  cobra.MinimumNArgs(1),
		DisableFlagsInUseLine: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			start := dir
			if start == "" {
				wd, err := os.Getwd()
				if err != nil {
					return err
				}
				start = wd
			}
			root, err := project.FindRoot(start)
			if err != nil {
				return err
			}
			log := audit.New(root)
			who := detect.Detect()

			// The policy applies to an agent only. A human at a terminal keeps
			// every power their shell gives them, and a build pipeline runs
			// whatever the pipeline file says.
			if who.Caller == detect.Agent {
				pol, perr := policy.Load(root)
				if perr != nil {
					return perr
				}
				if refusal := pol.Check(args); refusal != nil {
					rule := ""
					var r *policy.Refusal
					if errors.As(refusal, &r) {
						rule = r.Rule
					}
					_ = log.Write(audit.Record{
						Event:   audit.EventRefused,
						Caller:  who.Caller.String(),
						Reason:  who.Reason,
						Command: args,
						Detail:  rule,
					})
					return refusal
				}
			}

			st, _ := openStore(root)

			res, err := runtime.Resolve(cmd.Context(), st, runtime.Options{
				Dir:   start,
				Files: files,
			})
			if err != nil {
				return err
			}
			// A store that does not open makes every reference look missing.
			// The advice to set a value is wrong then, and it sends the
			// developer to write a value that is already there.
			if res.Err != nil && !allowMiss {
				return fmt.Errorf("the store could not be read, so no handle could be resolved: %w.\n"+
					"Check the key: SECRETVEIL_IDENTITY, SECRETVEIL_PASSPHRASE, or the OS keyring.\n"+
					"Run \"secretveil doctor\" to see which key sources this machine has", res.Err)
			}
			if len(res.Missing) > 0 && !allowMiss {
				return fmt.Errorf("the store holds no value for %s.\n"+
					"Run \"secretveil set <ref>\" to add it, or pass --allow-missing to start anyway",
					strings.Join(res.Missing, ", "))
			}

			errOut := cmd.ErrOrStderr()
			if !quiet {
				report(errOut, res)
			}

			out, err := runtime.Run(cmd.Context(), runtime.Config{
				Args:      args,
				Dir:       start,
				Env:       res.Env,
				Values:    res.Values,
				NoPTY:     noPTY,
				ForcePTY:  forcePTY,
				IdleFlush: idle,
			})
			if err != nil {
				return err
			}

			refs := make([]string, 0, len(res.Values))
			for ref := range res.Values {
				refs = append(refs, ref)
			}
			sort.Strings(refs)
			_ = log.Write(audit.Record{
				Event:    audit.EventRun,
				Caller:   who.Caller.String(),
				Reason:   who.Reason,
				Command:  args,
				Refs:     refs,
				ExitCode: &out.ExitCode,
			})

			if !quiet {
				for _, ref := range out.Skipped {
					fmt.Fprintf(errOut, "secretveil: the value of %s is too short to remove from the output safely. "+
						"It stays visible. Use a longer value.\n", ref)
				}
			}
			if out.ExitCode != 0 {
				return &exitError{code: out.ExitCode}
			}
			return nil
		},
	}

	cmd.Flags().StringSliceVar(&files, "env-file", nil,
		"the .env files to read, in load order (default .env and .env.local)")
	cmd.Flags().StringVar(&dir, "dir", "", "the working directory of the program (default the current one)")
	cmd.Flags().BoolVar(&noPTY, "no-pty", false, "use pipes, so stdout and stderr stay apart")
	cmd.Flags().BoolVar(&forcePTY, "pty", false, "use a terminal even when the output is a file or a pipe")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "print nothing of our own")
	cmd.Flags().BoolVar(&allowMiss, "allow-missing", false, "start even when the store holds no value for a handle")
	cmd.Flags().DurationVar(&idle, "idle-flush", 0,
		"how long the filter waits before it releases the bytes it holds (default 40ms)")
	return cmd
}

// report prints one short line about what run resolved. It never prints a
// value, only a count and a name.
func report(w io.Writer, res *runtime.Resolution) {
	if len(res.Files) == 0 {
		fmt.Fprintln(w, "secretveil: no .env or .npmrc file here. The program starts with the environment as it is.")
		return
	}
	names := make([]string, 0, len(res.Files))
	for _, p := range res.Files {
		names = append(names, filepath.Base(p))
	}
	fmt.Fprintf(w, "secretveil: %d secret(s) from %s\n", len(res.Values), strings.Join(names, ", "))
	if len(res.Skipped) > 0 {
		fmt.Fprintf(w, "secretveil: the environment already holds %s, so the file value was not used\n",
			strings.Join(res.Skipped, ", "))
	}
}

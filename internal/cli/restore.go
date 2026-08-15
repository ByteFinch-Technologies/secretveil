package cli

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/ByteFinch-Technologies/secretveil/internal/audit"
	"github.com/ByteFinch-Technologies/secretveil/internal/detect"
	"github.com/ByteFinch-Technologies/secretveil/internal/migrate"
	"github.com/spf13/cobra"
)

func newRestore() *cobra.Command {
	var dryRun bool
	var yes bool

	cmd := &cobra.Command{
		Use:   "restore [path]",
		Short: "Put the plaintext values back in the .env files",
		Long: `restore is the exact opposite of init. It reads every handle in every .env
file, asks the store for the value, and writes the value in place of the handle.

The result is the original file, byte for byte. This is how a developer who
tries secretveil and does not like it gets their project back, with an empty
diff.

restore needs no backup. The file with the handles and the store together hold
everything the original file held. It stops before it writes anything if the
store cannot supply every value, because a file that is half restored is worse
than a file that is not restored.

restore writes every secret back in the clear, so it needs a human caller, the
same as "get --reveal". An AI agent that could run it would need one command to
undo the whole tool. A caller with no terminal, or with the marker of an AI tool
in its environment, is refused and the refusal goes into the audit log.

Warning: after restore, your secrets are in the clear on disk again.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root, err := rootFrom(args)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			log := audit.New(root)
			who := detect.Detect()

			// A dry run writes nothing, so it is not a way out. It is left open
			// so that an agent can still say what restore would do.
			if !dryRun && who.Caller != detect.Human {
				why := fmt.Sprintf(
					"restore puts every secret back in the clear, so it needs a human at a terminal. "+
						"This caller looks like a %s, because %s. "+
						"Run it yourself in your own terminal, or use --dry-run to see what it would do",
					who.Caller, who.Reason)
				_ = log.Write(audit.Record{
					Event:  audit.EventRestore,
					Caller: who.Caller.String(),
					Reason: who.Reason,
					Detail: "refused: " + why,
				})
				return errors.New(why)
			}

			// The read goes to the encrypted file and not to the chain. A
			// variable in the environment is an override for one run of one
			// program. To write it into the file of the developer would be a
			// silent change of the project.
			_, file := openStore(root)
			ctx := ctxOrBackground(cmd.Context())

			// Ask first. The count comes from a dry run, so the question can
			// say how many values are about to land on disk in the clear.
			if !dryRun {
				preview, perr := migrate.Restore(ctx, file, root, true)
				if perr != nil {
					return perr
				}
				if len(preview.Files) == 0 {
					fmt.Fprintf(out, "There is no handle to restore under %s.\n", root)
					return nil
				}
				q := fmt.Sprintf("Put %d secrets back in the clear, in %d files?",
					preview.Handles, len(preview.Files))
				if cerr := confirm(cmd.InOrStdin(), out, yes, q); cerr != nil {
					return cerr
				}
			}

			res, err := migrate.Restore(ctx, file, root, dryRun)
			if err != nil {
				return err
			}
			if len(res.Files) == 0 {
				fmt.Fprintf(out, "There is no handle to restore under %s.\n", root)
				return nil
			}

			verb := "restored"
			if dryRun {
				verb = "would restore"
			}
			fmt.Fprintf(out, "%s %d handles in %d files:\n", verb, res.Handles, len(res.Files))
			for _, p := range res.Files {
				if rel, rerr := filepath.Rel(root, p); rerr == nil {
					p = rel
				}
				fmt.Fprintf(out, "  %s\n", p)
			}
			if dryRun {
				fmt.Fprintln(out, "\nThis was a dry run. Nothing changed.")
				return nil
			}
			_ = log.Write(audit.Record{
				Event:  audit.EventRestore,
				Caller: who.Caller.String(),
				Reason: who.Reason,
				Detail: fmt.Sprintf("%d handles in %d files", res.Handles, len(res.Files)),
			})
			fmt.Fprintln(out, "\nYour secrets are in the clear on disk again.")
			return nil
		},
	}

	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would change and write nothing")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "do not ask for confirmation")
	return cmd
}

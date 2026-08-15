package cli

import (
	"fmt"
	"path/filepath"

	"github.com/ByteFinch-Technologies/secretveil/internal/migrate"
	"github.com/spf13/cobra"
)

func newRestore() *cobra.Command {
	var dryRun bool

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

Warning: after restore, your secrets are in the clear on disk again.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root, err := rootFrom(args)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()

			// The read goes to the encrypted file and not to the chain. A
			// variable in the environment is an override for one run of one
			// program. To write it into the file of the developer would be a
			// silent change of the project.
			_, file := openStore(root)

			res, err := migrate.Restore(ctxOrBackground(cmd.Context()), file, root, dryRun)
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
			fmt.Fprintln(out, "\nYour secrets are in the clear on disk again.")
			return nil
		},
	}

	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would change and write nothing")
	return cmd
}

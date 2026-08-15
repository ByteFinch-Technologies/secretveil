package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ByteFinch-Technologies/secretveil/internal/audit"
	"github.com/ByteFinch-Technologies/secretveil/internal/detect"
	"github.com/ByteFinch-Technologies/secretveil/internal/store"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func newSet() *cobra.Command {
	var from string
	var raw bool

	cmd := &cobra.Command{
		Use:   "set <ref>",
		Short: "Put one secret in the store",
		Long: `set writes one value into the encrypted store, under the reference you give.

The value never comes from the command line. Every user on the machine can read
the arguments of a running program, and the shell keeps them in its history
file. So set reads the value from one of three places:

  * the terminal, with no echo, when you run it by hand
  * standard input, when you pipe a value in
  * a file, with --from-file

A newline at the end of the value is removed, because a pasted value nearly
always carries one and almost no secret needs one. Use --raw to keep every byte.

After set, put the handle in your .env file by hand:

  API_KEY=sv://api_key`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ref := args[0]
			if !store.ValidRef(ref) {
				return fmt.Errorf(
					"%q is not a valid reference. Use lower case letters, digits, and the characters _ - .", ref)
			}
			root, err := rootFrom(nil)
			if err != nil {
				return err
			}
			value, err := readSecret(cmd, from, ref)
			if err != nil {
				return err
			}
			if !raw {
				value = strings.TrimRight(value, "\r\n")
			}
			if value == "" {
				return errors.New("the value is empty, so nothing was written")
			}

			_, file := openStore(root)
			if err := file.Set(ctxOrBackground(cmd.Context()), ref, value); err != nil {
				return err
			}
			// The message names the reference and the length. It never prints
			// the value, because the terminal of a developer is often shared
			// with an agent that reads the same window.
			fmt.Fprintf(cmd.OutOrStdout(), "Wrote %s to the store. The value is %d bytes.\n", ref, len(value))
			return nil
		},
	}

	cmd.Flags().StringVar(&from, "from-file", "", "read the value from a file. Use - for standard input")
	cmd.Flags().BoolVar(&raw, "raw", false, "keep every byte, including a newline at the end")
	return cmd
}

// readSecret returns the value for set, from the right source.
func readSecret(cmd *cobra.Command, from, ref string) (string, error) {
	if from != "" && from != "-" {
		body, err := os.ReadFile(from)
		if err != nil {
			return "", err
		}
		return string(body), nil
	}

	in := cmd.InOrStdin()
	f, ok := in.(*os.File)
	if from == "-" || !ok || !term.IsTerminal(int(f.Fd())) {
		body, err := io.ReadAll(in)
		if err != nil {
			return "", err
		}
		return string(body), nil
	}

	fmt.Fprintf(cmd.ErrOrStderr(), "Value for %s (the terminal does not show it): ", ref)
	body, err := term.ReadPassword(int(f.Fd()))
	fmt.Fprintln(cmd.ErrOrStderr())
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func newList() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Print the name of every secret in the store",
		Long: `list prints the reference of every secret in the store of this project. It
prints no values, so it is safe to run in front of anyone.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			root, err := rootFrom(nil)
			if err != nil {
				return err
			}
			_, file := openStore(root)
			refs, err := file.List(ctxOrBackground(cmd.Context()))
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if len(refs) == 0 {
				fmt.Fprintln(out, "The store is empty. Run \"secretveil init\" to fill it.")
				return nil
			}
			for _, ref := range refs {
				fmt.Fprintln(out, ref)
			}
			return nil
		},
	}
	return cmd
}

func newGet() *cobra.Command {
	var reveal bool

	cmd := &cobra.Command{
		Use:   "get <ref>",
		Short: "Print one secret. Needs a human at a terminal.",
		Long: `get prints one plaintext value on standard output.

This command undoes everything the rest of the tool does, so it asks for two
things. It needs the --reveal flag, and it needs a human caller. A caller with
no terminal, or with the marker of an AI tool in its environment, is refused and
the refusal goes into the audit log.

Use get when you must copy a value into a dashboard by hand. Do not use it in a
script and do not use it in a pipeline. Use "secretveil run" there. It gives the
value to the child program and keeps it out of the output.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root, err := rootFrom(nil)
			if err != nil {
				return err
			}
			log := audit.New(root)
			who := detect.Detect()

			refuse := func(why string) error {
				_ = log.Write(audit.Record{
					Event:  audit.EventReveal,
					Caller: who.Caller.String(),
					Reason: who.Reason,
					Refs:   []string{args[0]},
					Detail: "refused: " + why,
				})
				return errors.New(why)
			}
			if !reveal {
				return refuse("get prints a secret in the clear. Add --reveal if that is what you want")
			}
			if who.Caller != detect.Human {
				return refuse(fmt.Sprintf(
					"get needs a human at a terminal, and this caller looks like a %s, because %s",
					who.Caller, who.Reason))
			}

			chain, _ := openStore(root)
			value, err := chain.Get(ctxOrBackground(cmd.Context()), args[0])
			if err != nil {
				return err
			}
			_ = log.Write(audit.Record{
				Event:  audit.EventReveal,
				Caller: who.Caller.String(),
				Reason: who.Reason,
				Refs:   []string{args[0]},
			})
			// The value goes out with no newline, so a shell substitution gets
			// the value and nothing else.
			fmt.Fprint(cmd.OutOrStdout(), value)
			return nil
		},
	}

	cmd.Flags().BoolVar(&reveal, "reveal", false, "yes, print the secret in the clear")
	return cmd
}

func newRemove() *cobra.Command {
	var yes bool

	cmd := &cobra.Command{
		Use:     "rm <ref>",
		Aliases: []string{"remove", "delete"},
		Short:   "Remove one secret from the store",
		Long: `rm removes one value from the store. The handle in your .env file stays, so
"secretveil run" will report the reference as missing until you set it again or
remove the line.

The value is gone for good. There is no other copy.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ref := args[0]
			root, err := rootFrom(nil)
			if err != nil {
				return err
			}
			_, file := openStore(root)
			ctx := ctxOrBackground(cmd.Context())

			if _, err := file.Get(ctx, ref); err != nil {
				if errors.Is(err, store.ErrNotFound) {
					return fmt.Errorf("the store holds no secret called %q", ref)
				}
				return err
			}
			if !yes {
				q := fmt.Sprintf("Remove %s from the store? There is no other copy.", ref)
				if err := confirm(cmd.InOrStdin(), cmd.OutOrStdout(), false, q); err != nil {
					return errors.New("rm stopped, and nothing changed")
				}
			}
			if err := file.Delete(ctx, ref); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Removed %s from the store.\n", ref)
			return nil
		},
	}

	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "do not ask for confirmation")
	return cmd
}

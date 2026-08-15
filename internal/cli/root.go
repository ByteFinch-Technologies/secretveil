// Package cli holds the command surface.
package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Version is set by the linker at release time.
var Version = "dev"

func newRoot() *cobra.Command {
	root := &cobra.Command{
		Use:   "secretveil",
		Short: "Let an AI agent use your secrets without reading them",
		Long: `secretveil keeps the plaintext value off disk.

The .env file in your project holds a handle for each secret, so every AI tool
reads it safely with no integration. The real values live in your OS keychain
and reach the program through "secretveil run".`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(
		newVersion(),
		newPlan(),
		newInit(),
		newRun(),
		newRestore(),
		newSet(),
		newGet(),
		newList(),
		newRemove(),
		newDoctor(),
	)
	return root
}

// Execute runs the command line.
func Execute() {
	err := newRoot().Execute()
	if err == nil {
		return
	}
	// A child that failed is not a failure of secretveil. The exit code of the
	// child goes out as it is and no message goes with it, so a script behaves
	// the same with secretveil in front of the command as without it.
	var ex *exitError
	if errors.As(err, &ex) {
		os.Exit(ex.code)
	}
	fmt.Fprintln(os.Stderr, "secretveil:", err)
	os.Exit(1)
}

func newVersion() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintln(cmd.OutOrStdout(), Version)
		},
	}
}

package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/ByteFinch-Technologies/secretveil/internal/classify"
	"github.com/ByteFinch-Technologies/secretveil/internal/migrate"
	"github.com/spf13/cobra"
)

func newPlan() *cobra.Command {
	var asJSON, showProjection bool

	cmd := &cobra.Command{
		Use:   "plan [path]",
		Short: "Show what init would do. Writes nothing.",
		Long: `plan finds every .env file, classifies every variable, and prints the
result. It writes nothing and it changes nothing, so it is safe to run at any
time.

The default output never prints a secret value. It prints the key, the class,
the rule that fired and the shape of the value. Use --projection to print the
file as the agent would read it, which is safe because every secret in it is
already replaced by a handle.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root := "."
			if len(args) == 1 {
				root = args[0]
			}
			p, err := migrate.BuildPlan(root)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(p)
			}
			if showProjection {
				writeProjection(out, p)
				return nil
			}
			writeTable(out, p, root)
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the plan as JSON")
	cmd.Flags().BoolVar(&showProjection, "projection", false, "print each file as the agent would read it")
	return cmd
}

func writeTable(out io.Writer, p *migrate.Plan, root string) {
	if len(p.Files) == 0 {
		fmt.Fprintf(out, "No .env file with values found under %s\n", root)
		return
	}
	for _, f := range p.Files {
		rel, err := filepath.Rel(root, f.Path)
		if err != nil {
			rel = f.Path
		}
		fmt.Fprintf(out, "\n%s\n", rel)
		w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "  KEY\tCLASS\tRULE\tSHAPE")
		for _, e := range f.Entries {
			shapeText := ""
			if e.Decision.Class != classify.Open {
				shapeText = fmt.Sprintf("%d chars, %s, entropy %.1f",
					e.Decision.Shape.Length, e.Decision.Shape.Charset, e.Decision.Shape.Entropy)
			}
			fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n", e.Key, e.Decision.Class, e.Decision.Rule, shapeText)
		}
		w.Flush()
	}

	fmt.Fprintf(out, "\n%d files, %d variables: %d open, %d partial, %d veiled.\n",
		p.Counts.Files,
		p.Counts.Open+p.Counts.Partial+p.Counts.Veiled,
		p.Counts.Open, p.Counts.Partial, p.Counts.Veiled)

	if len(p.Links) > 0 {
		fmt.Fprintf(out, "\n%d .env files are symbolic links, and secretveil never follows one.\n"+
			"The file a link points at can be anywhere on the machine, so these stay as they are:\n",
			len(p.Links))
		for _, l := range p.Links {
			if rel, err := filepath.Rel(root, l); err == nil {
				l = rel
			}
			fmt.Fprintf(out, "  %s\n", l)
		}
	}

	if dupes := p.DuplicateRefs(); len(dupes) > 0 {
		fmt.Fprintf(out, "\n%d reference names collide. init must rename them first:\n", len(dupes))
		for ref, owners := range dupes {
			fmt.Fprintf(out, "  %s  <-  %s\n", ref, strings.Join(owners, ", "))
		}
	}
}

func writeProjection(out io.Writer, p *migrate.Plan) {
	for _, f := range p.Files {
		fmt.Fprintf(out, "# ---- %s ----\n", f.Path)
		for _, e := range f.Entries {
			line := e.Key + "=" + e.Projected
			if e.Decision.Class != classify.Open {
				line += "    # " + e.Decision.Shape.Comment()
			}
			fmt.Fprintln(out, line)
		}
		fmt.Fprintln(out)
	}
}

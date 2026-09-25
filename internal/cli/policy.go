package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/ByteFinch-Technologies/secretveil/internal/audit"
	"github.com/ByteFinch-Technologies/secretveil/internal/detect"
	"github.com/ByteFinch-Technologies/secretveil/internal/policy"
	"github.com/ByteFinch-Technologies/secretveil/internal/project"
	"github.com/ByteFinch-Technologies/secretveil/internal/store/agefile"
)

func newPolicy() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Approve the policy file of this project",
	}
	cmd.AddCommand(newPolicyApprove())
	return cmd
}

func newPolicyApprove() *cobra.Command {
	return &cobra.Command{
		Use:   "approve",
		Short: "Let a policy file that turns off a default rule apply to an agent",
		Long: `approve records that a human wrote the policy file of this project.

The policy file sits inside the project, and an agent writes files there all
day. So a file that turns off a default rule, for example with enforce = false
or a shorter deny list, does not apply to an agent until a human approves it.
Until then, an agent gets the default rules as well as the rules in the file.

approve needs a human at a terminal. It stores the SHA-256 of the file inside
the encrypted store, with the modification time of the file and, on Unix, its
inode. A change to the file cancels the approval, so run approve again after
each change. A copy of the file that is removed and written back is a new copy,
and it needs a new approval too.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			root, err := rootFrom(nil)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			log := audit.New(root)
			who := detect.Detect()

			p, sum, stamp, err := policy.LoadWithStamp(root)
			if err != nil {
				return err
			}
			if sum == "" {
				return fmt.Errorf("this project has no %s/%s, so there is nothing to approve", project.Dir, policy.FileName)
			}
			reasons := policy.Weaker(p)
			if len(reasons) == 0 {
				fmt.Fprintln(out, "The policy file keeps every default rule, so it needs no approval.")
				return nil
			}

			if who.Caller != detect.Human {
				why := fmt.Sprintf("policy approve needs a human at a terminal, and this caller looks like %s, because %s",
					who.Caller.WithArticle(), who.Reason)
				_ = log.Write(audit.Record{
					Event:  audit.EventPolicy,
					Caller: who.Caller.String(),
					Reason: who.Reason,
					Detail: "refused: " + why,
				})
				return errors.New(why)
			}

			_, file := openStore(root)
			if _, err := os.Stat(file.Path()); err != nil {
				return fmt.Errorf("this project has no store yet. Run \"secretveil init\" first")
			}
			if err := file.SetMeta(policy.ApprovalKey, stamp); err != nil {
				return err
			}
			_ = log.Write(audit.Record{
				Event:  audit.EventPolicy,
				Caller: who.Caller.String(),
				Reason: who.Reason,
				Detail: fmt.Sprintf("approved sha256 %s: %s", sum, summary(reasons)),
			})

			fmt.Fprintf(out, "Approved %s. An agent now gets these settings:\n",
				filepath.Join(project.Dir, policy.FileName))
			for _, r := range reasons {
				fmt.Fprintf(out, "  %s\n", r)
			}
			fmt.Fprintln(out, "A change to the file, or a new copy of it, cancels this approval.")
			return nil
		},
	}
}

// agentPolicy returns the rules that apply to an agent in this project.
//
// written is the file as it is. inForce is the set that applies. They are the
// same unless the file turns off a default rule and no human approved it. Then
// inForce is the floor, and reasons names what the file turned off. stamp names
// the copy of the file that was read, and it is empty when there is no file.
func agentPolicy(root string, file *agefile.Store) (written, inForce *policy.Policy, reasons []string, stamp string, err error) {
	written, _, stamp, err = policy.LoadWithStamp(root)
	if err != nil {
		return nil, nil, nil, "", err
	}
	reasons = policy.Weaker(written)
	if len(reasons) == 0 || approved(file, stamp) {
		return written, written, nil, stamp, nil
	}
	return written, policy.Floor(written), reasons, stamp, nil
}

// approved reports whether the store holds this stamp as the approved policy.
// A store that does not open gives no approval.
//
// The stamp names one copy of the file, and not only its bytes. See
// policy.LoadWithStamp.
func approved(file *agefile.Store, stamp string) bool {
	if stamp == "" || file == nil {
		return false
	}
	got, err := file.Meta(policy.ApprovalKey)
	return err == nil && got == stamp
}

// forget removes a stored approval that does not name this copy of the file.
//
// Such an approval is of no use, because the file it names is gone or has
// changed. If it stays, a later copy that gets the same stamp gets the
// approval too. An error is not reported: the approval does not match, so
// the floor applies either way.
func forget(file *agefile.Store, stamp string) {
	if file == nil {
		return
	}
	got, err := file.Meta(policy.ApprovalKey)
	if err != nil || got == "" || got == stamp {
		return
	}
	_ = file.SetMeta(policy.ApprovalKey, "")
}

// agentCheck applies the rules to a command that an agent wants to run. It
// returns the refusal, or nil, and the detail for the audit log.
func agentCheck(root string, file *agefile.Store, args []string) (*policy.Refusal, string, error) {
	written, inForce, reasons, stamp, err := agentPolicy(root, file)
	if err != nil {
		return nil, "", err
	}
	forget(file, stamp)
	var r *policy.Refusal
	if !errors.As(inForce.Check(args), &r) {
		return nil, "", nil
	}
	if len(reasons) == 0 || written.Check(args) != nil {
		return r, r.Rule, nil
	}
	// The file allows the command and the floor does not. Say so, or the
	// developer reads the file, sees that it allows the command, and cannot
	// see why it was refused.
	tail := "policy file allows it, but no human approved that file, and " + summary(reasons)
	return &policy.Refusal{
		Program: r.Program,
		Rule:    r.Rule,
		Advice:  "The " + tail + ". If a person wrote the file, that person can run \"secretveil policy approve\".",
	}, r.Rule + "; the " + tail, nil
}

// summary names the first reason and counts the rest, so one line holds it.
func summary(reasons []string) string {
	switch len(reasons) {
	case 0:
		return ""
	case 1:
		return reasons[0]
	default:
		return fmt.Sprintf("%s, and %d more", reasons[0], len(reasons)-1)
	}
}

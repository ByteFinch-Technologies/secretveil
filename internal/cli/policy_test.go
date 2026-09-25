package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ByteFinch-Technologies/secretveil/internal/policy"
	"github.com/ByteFinch-Technologies/secretveil/internal/store/agefile"
	"github.com/ByteFinch-Technologies/secretveil/internal/store/keyring"
)

// TestAStaleApprovalIsForgotten covers a finding of the review of issue 75.
// An approval that does not name the file on disk is removed when an agent
// runs, so a later copy with the same stamp cannot get it.
func TestAStaleApprovalIsForgotten(t *testing.T) {
	t.Setenv(agefile.EnvIdentity, "")
	t.Setenv(agefile.EnvPassphrase, "")
	root := t.TempDir()
	dir := filepath.Join(root, ".secretveil")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	pol := filepath.Join(dir, policy.FileName)
	if err := os.WriteFile(pol, []byte("[agent]\nenforce = false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	file := agefile.New(filepath.Join(dir, agefile.FileName), keyring.NewFake(), "test.identity")
	shell := []string{"sh", "-c", "echo x"}

	_, _, stamp, err := policy.LoadWithStamp(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.SetMeta(policy.ApprovalKey, stamp); err != nil {
		t.Fatal(err)
	}
	if r, _, err := agentCheck(root, file, shell); err != nil || r != nil {
		t.Fatalf("the approved file did not apply: %v %v", r, err)
	}
	if got, _ := file.Meta(policy.ApprovalKey); got != stamp {
		t.Fatalf("a run removed an approval that matches the file: got %q", got)
	}

	for name, stale := range map[string]func(){
		"another copy":   func() {},
		"no file at all": func() { _ = os.Remove(pol) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := file.SetMeta(policy.ApprovalKey, "0000:1.2.3"); err != nil {
				t.Fatal(err)
			}
			stale()
			if _, _, err := agentCheck(root, file, shell); err != nil {
				t.Fatal(err)
			}
			if got, _ := file.Meta(policy.ApprovalKey); got != "" {
				t.Errorf("the stale approval %q stayed in the store", got)
			}
		})
	}
}

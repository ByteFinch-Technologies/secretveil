package cli

import (
	"path/filepath"

	"github.com/ByteFinch-Technologies/secretveil/internal/project"
	"github.com/ByteFinch-Technologies/secretveil/internal/store"
	"github.com/ByteFinch-Technologies/secretveil/internal/store/agefile"
	"github.com/ByteFinch-Technologies/secretveil/internal/store/envstore"
	"github.com/ByteFinch-Technologies/secretveil/internal/store/keyring"
)

// rootFrom returns the project root for a command that takes an optional path.
//
// The command walks up from the given directory, so it works from a
// subdirectory of the project in the same way that git does.
func rootFrom(args []string) (string, error) {
	start := "."
	if len(args) == 1 && args[0] != "" {
		start = args[0]
	}
	return project.FindRoot(start)
}

// openStore builds the store chain for a project.
//
// The order is deliberate:
//
//   - The environment comes first, so a build server can pass a secret in
//     without a file and without a keychain.
//   - The encrypted file comes second. It is the normal source on a
//     workstation, and it is the only one that a write can reach.
//
// A store that is not available on this machine drops out of the chain, so an
// empty environment cannot hide the file behind it.
func openStore(root string) (store.Store, *agefile.Store) {
	file := agefile.New(
		filepath.Join(root, project.Dir, agefile.FileName),
		keyring.New(),
		project.KeyEntry(root),
	)
	return store.NewChain(envstore.New(), file), file
}

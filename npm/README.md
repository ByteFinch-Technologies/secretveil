# The npm packages

This directory is how a developer gets secretveil with `npx`. It is not the source of the
program. The program is Go, and it is in `cmd/` and `internal/`.

## The layout

Five packages go to npm.

| Package | What is in it | Made by |
|---|---|---|
| `secretveil` | A Node shim and nothing else. About 3 kB. | Checked in, at `npm/secretveil/` |
| `@secretveil/darwin-arm64` | One binary. | `npm/build.mjs` |
| `@secretveil/darwin-x64` | One binary. | `npm/build.mjs` |
| `@secretveil/linux-x64` | One binary. | `npm/build.mjs` |
| `@secretveil/linux-arm64` | One binary. | `npm/build.mjs` |

`secretveil` names the four as `optionalDependencies`. Each platform package carries an `os`
and a `cpu` field, so npm installs the one that matches the machine and skips the other
three. `optionalDependencies` is what lets the install finish on a machine we do not support
yet, such as Windows. This is the pattern esbuild uses.

`npm/platforms/` is a build result and is not checked in.

## Make them

```sh
goreleaser release --snapshot --clean --skip=sign,publish
node npm/build.mjs 0.1.0
```

`build.mjs` reads `dist/artifacts.json` rather than the directory names, because goreleaser
puts the processor variant in a directory name and that name changes when the Go release
changes. It writes the version into every package, and it then asks `file` whether each
binary really is for the platform of the package that holds it. A Linux user who gets a
macOS binary sees no warning at all, so that check is worth the second it costs.

## Publish them

The platform packages go first. The main package depends on them, and a developer who
installs `secretveil` before its binary exists gets an error instead of a program.

```sh
for d in npm/platforms/*; do npm publish "./$d" --access public --provenance; done
npm publish ./npm/secretveil --access public --provenance
```

Keep the `./`. A path of the form `a/b` with two parts is a GitHub repository to npm, not a
directory, so `npm publish npm/secretveil` tries to reach `github.com/npm/secretveil` and
fails with a git error that does not say why.

`--provenance` makes npm record which workflow, on which commit, built the package. It works
only from CI with `id-token: write`, and only from a **public** repository. npm answers a
private one with "Only public source repositories are supported when publishing with
provenance". The workflow therefore adds the flag only when the repository is public, and
says in the log when it does not.

## The first publish is done

v0.1.0 went to the registry on 2026-08-18. All five packages carry a SLSA provenance
statement, and `npm install secretveil` on darwin/arm64 fetched the shim and its one platform
package and printed `0.1.0`.

The section that follows is what the next release needs. Read "What the first publish taught
us" below before you make a token, because two things cost time that do not have to cost it
again.

## What the next release needs

1. **Authentication.** The token that did the first publish is a granular access token with a
   short life, so it is probably dead by now. Do not make another one. Set up **trusted
   publishing** instead, per package, at `https://www.npmjs.com/package/<name>/access`, for
   all five packages. npm then trusts this repository and this workflow through OIDC. There
   is no token to make, to store or to rotate, and provenance is written with no
   `--provenance` flag.
2. **Nothing else.** The organisation exists, the repository is public, and the workflow is
   proven. Tag `vX.Y.Z` and the release runs.

Do not make a classic token. npm is withdrawing them. The account pages stop making them in
August 2026, and they stop working for a publish in January 2027.

## What the first publish taught us

**A token that authenticates can still be refused, and npm says 404.** The first attempt
failed on the first package with
`E404 Not Found - PUT https://registry.npmjs.org/@secretveil%2fdarwin-arm64`. That reads like
a missing package, and it is not. npm answers an unauthorised write with 404 rather than 403,
so that a stranger cannot learn which private packages exist. The token was valid, it had
authenticated, and it did not carry write permission for the scope. A replacement token
published all five with no other change.

Two things this rules out, so nobody has to test them again:

- The **Organizations** permission is not the one. npm's own documentation says that
  organisation access "does not give the token the right to publish packages managed by the
  organization". Leave it at no access. The permission that matters is **Packages and
  scopes**, and it has to be write.
- The **organisation** was never the fault. The account was the owner of the org and a member
  of the default `developers` team, which has read and write on every package under the
  scope.

**The failure was safe, and that was luck, not design.** It stopped on the first of five
packages, so the registry was untouched and the tag could be reused. Had it stopped on the
fifth, `secretveil` would have been on the registry with four of its platform packages
missing, and a published version cannot be replaced. Keep the platform packages first in the
publish loop for this reason, and treat any publish failure as a reason to check the registry
before doing anything else.

**A new package can 404 for minutes after npm says it published.** `@secretveil/darwin-arm64`
reported `+ @secretveil/darwin-arm64@0.1.0`, and appeared on the organisation page, while the
public read endpoint still answered 404. It resolved about seven minutes later. Do not read a
404 straight after a publish as a failed publish. Read the organisation package list first,
which is authoritative, then wait.

## What the dry run proved

On 2026-08-16, with the four binaries cross compiled from the `main` commit and no registry
involved:

- `node npm/build.mjs 0.1.0` wrote all four platform packages and passed its own `file`
  check, so no package holds a binary for another platform.
- `npm pack` made five tarballs. The four platform ones hold `bin/secretveil`,
  `package.json` and `LICENSE`. The main one holds those plus `index.js` and `README.md`,
  and is 3 kB.
- Installing the `darwin-arm64` tarball and the main tarball into an empty project put a
  `node_modules/.bin/secretveil` link in place, and `secretveil version` printed `0.1.0`.
  That is the whole chain, so the shim resolves the platform package and the `-X` version
  stamp reaches the binary.

The registry names are free. `secretveil` and `@secretveil/darwin-arm64` both answer 404.

## Test the shim without publishing

```sh
node npm/build.mjs 0.1.0
npm pack --pack-destination /tmp ./npm/platforms/darwin-arm64 ./npm/secretveil
cd /tmp && npm install ./secretveil-darwin-arm64-0.1.0.tgz ./secretveil-0.1.0.tgz
./node_modules/.bin/secretveil version
```

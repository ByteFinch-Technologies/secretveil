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

## Before the first publish

Three things have to be true and none of them is in this repository:

1. **The `secretveil` npm organisation exists**, because `@secretveil/...` is a scoped name.
   Make it at <https://www.npmjs.com/org/create>. The free tier is enough for a public
   package.
2. **The workflow can authenticate.** There are two ways, and the second is better:
   - An **`NPM_TOKEN` secret** on the GitHub repository, of type "Automation", so that two
     factor authentication does not stop the workflow. Set it with
     `gh secret set NPM_TOKEN`, which reads the value from standard input and never puts it
     in a command line.
   - **Trusted publishing**, which npm made generally available in July 2025. npm trusts a
     named workflow in a named repository through OIDC, so there is no token to make, to
     store or to rotate, and provenance is written with no `--provenance` flag. Set it up
     per package at `https://www.npmjs.com/package/<name>/access`. It needs the package to
     exist already, so the first publish still uses a token.
3. **The repository is public**, if the packages are to carry provenance. This is a
   decision, not a step. A private repository still publishes; the packages simply have no
   provenance statement, and the `repository` link in every package points at a page that
   answers 404 for everyone who is not a member.

Until the token exists, the publish job in `.github/workflows/release.yml` is skipped. It
checks for the token and says so in the log.

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

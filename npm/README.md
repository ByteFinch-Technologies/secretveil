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
only from CI with `id-token: write`.

## Before the first publish

Two things have to exist and neither is in this repository:

1. **The `secretveil` npm organisation**, because `@secretveil/...` is a scoped name.
2. **An `NPM_TOKEN` secret** on the GitHub repository, of type "Automation", so that two
   factor authentication does not stop the workflow.

Until both exist, the publish job in `.github/workflows/release.yml` is skipped. It checks
for the token and says so in the log.

## Test the shim without publishing

```sh
node npm/build.mjs 0.1.0
npm pack --pack-destination /tmp ./npm/platforms/darwin-arm64 ./npm/secretveil
cd /tmp && npm install ./secretveil-darwin-arm64-0.1.0.tgz ./secretveil-0.1.0.tgz
./node_modules/.bin/secretveil version
```

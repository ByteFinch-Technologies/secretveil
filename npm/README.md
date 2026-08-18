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

Three things have to be true. Two of them are now done.

1. **The `secretveil` npm organisation exists.** Done on 2026-08-16, on the free tier.
   `@secretveil/...` is a scoped name, and a scope has to belong to an organisation or to a
   user. The free tier holds any number of public packages.
2. **The workflow can authenticate.** Open. This is the one step that is left, and it needs
   a person, because npm asks for the second factor before it makes a token.
   - For the **first** publish, make a **granular access token** at
     <https://www.npmjs.com/settings/umer-bytefinch/tokens/new>. Give it write permission on
     the `@secretveil` scope and on the `secretveil` package, and nothing else. Install it
     with `gh secret set NPM_TOKEN --repo ByteFinch-Technologies/secretveil`, which reads
     the value from standard input and puts it in no command line and in no shell history.
     Read the lifetime that npm offers. npm limits a granular token that is made for
     automation to a short life, so treat this token as one for the first publish and not as
     one for the year.
   - For **every publish after that**, use **trusted publishing**, which npm made generally
     available in July 2025. npm trusts a named workflow in a named repository through OIDC,
     so there is no token to make, to store or to rotate, and provenance is written with no
     `--provenance` flag. Set it up per package at
     `https://www.npmjs.com/package/<name>/access`, for all five packages. It needs the
     package to exist, which is why the first publish still uses a token.
   - Do not make a classic token. npm is withdrawing them. The account pages stop making
     them in August 2026, and they stop working for a publish in January 2027. An earlier
     version of this file asked for an "Automation" classic token. That advice is wrong now.
3. **The repository is public.** Done on 2026-08-16, after a scan of every commit found no
   credential and no business content. The packages therefore carry provenance, and the
   `repository` link in each package points at a page that anyone can read.

Until the token exists, the publish job in `.github/workflows/release.yml` is skipped. It
checks for the token and says so in the log. Tag `v0.1.0` only after the token is in place.
A tag that is spent on a release with no packages cannot be spent again, and the `dist`
artifact of that run is kept for one day only.

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

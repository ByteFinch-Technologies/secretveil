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

CI publishes. This section is for the rare case where a release stops part way and you have
to finish it by hand.

The platform packages go first. The main package depends on them, and a developer who
installs `secretveil` before its binary exists gets an error instead of a program.

```sh
for d in npm/platforms/*; do npm publish "./$d" --access public; done
npm publish ./npm/secretveil --access public
```

Keep the `./`. A path of the form `a/b` with two parts is a GitHub repository to npm, not a
directory, so `npm publish npm/secretveil` tries to reach `github.com/npm/secretveil` and
fails with a git error that does not say why.

There is no `--provenance` flag here. Provenance records which workflow, on which commit,
built the package, so only CI can make one. A publish from a laptop gets none, and it is
therefore a step down from a tagged release. Use it to recover, not to release.

## Trusted publishing

v0.1.0 went to the registry on 2026-08-18. All five packages carry a SLSA provenance
statement, and the release workflow holds no npm credential. It asks GitHub for a short lived identity
token, and npm trades that token for the right to publish. There is nothing to store and
nothing to rotate, and npm writes the provenance statement without being asked for it.

npm keeps one trusted publisher **for each package**, so all five need the same settings.
Set each one at `https://www.npmjs.com/package/<name>/access`, in the trusted publisher
section:

| Field | Value |
|---|---|
| Publisher | GitHub Actions |
| Organization or user | `ByteFinch-Technologies` |
| Repository | `secretveil` |
| Workflow filename | `release.yml` |
| Environment | leave it empty |
| Allowed actions | `npm publish` |

The five packages are `secretveil`, `@secretveil/darwin-arm64`, `@secretveil/darwin-x64`,
`@secretveil/linux-x64` and `@secretveil/linux-arm64`.

Five things about this cost time if you do not know them first:

- The **workflow filename** is the name of the file alone. It is `release.yml`, not
  `.github/workflows/release.yml`.
- **Allowed actions** has to be set. npm refuses a configuration made after 20 May 2026 that
  names no action.
- The package has to **exist** before it can hold a trusted publisher, so a first version
  cannot go out by OIDC alone. A new platform package needs one publish by another route,
  and a configuration after it.
- Trusted publishing needs **npm 11.5.1 or later** and **Node 22.14.0 or later**. An older
  npm does not report that it cannot do it. It asks for a token instead, and the publish
  then fails with a 404 that reads like a missing package.
- The page is behind a **second authentication**. npm asks for the security key again before
  it shows the access page of a package.

Do not make a classic token. npm is withdrawing them. The account pages stop making them in
August 2026, and they stop working for a publish in January 2027.

## Three things the first publish taught us

**npm answers an unauthorised write with 404, not 403,** so that a stranger cannot learn
which private packages exist. `E404 Not Found - PUT .../@secretveil%2fdarwin-arm64` meant a
token without write permission, not a missing package. On a classic token the permission that
matters is **Packages and scopes**, set to write. The **Organizations** permission is not it,
and npm's own documentation says so.

**Publish the platform packages first, and check the registry after any failure.** The first
attempt stopped on the first of five, so the registry was untouched and the tag could be
reused. Had it stopped on the fifth, `secretveil` would have been published with four
platform packages missing, and a published version cannot be replaced.

**A new package can answer 404 for minutes after npm says it published.** Read the
organisation package list, which is authoritative, then wait. Do not read that 404 as a
failed publish.

## Test the shim without publishing

```sh
node npm/build.mjs 0.1.0
npm pack --pack-destination /tmp ./npm/platforms/darwin-arm64 ./npm/secretveil
cd /tmp && npm install ./secretveil-darwin-arm64-0.1.0.tgz ./secretveil-0.1.0.tgz
./node_modules/.bin/secretveil version
```

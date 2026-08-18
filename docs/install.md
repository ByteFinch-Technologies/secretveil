# Install

secretveil is one program with no runtime dependency. Pick the way that fits your project.

## With npm

This is the usual way. It needs Node.js 18 or later.

```sh
npx secretveil doctor              # run it once, install nothing
npm install --save-dev secretveil  # one project, one version for the whole team
npm install --global secretveil    # every project on this machine
```

The `secretveil` package holds a small Node file and no binary. It names four platform
packages as `optionalDependencies`, and npm installs only the one that matches the machine:

| Package | Machine |
|---|---|
| `@secretveil/darwin-arm64` | macOS, Apple silicon |
| `@secretveil/darwin-x64` | macOS, Intel |
| `@secretveil/linux-x64` | Linux, Intel or AMD |
| `@secretveil/linux-arm64` | Linux, ARM |

Each package is published from GitHub Actions through npm trusted publishing, so npm records
which workflow built it, from which commit, and no publish credential exists to be stolen.
The provenance badge is on the npm page.

### Windows

There is no Windows binary yet. It is planned for v0.3. On Windows, use the Windows Subsystem
for Linux, where the Linux package works.

The install itself does not fail on Windows. `optionalDependencies` lets npm finish, and the
error comes only when you run the command. That way `npm install` in a mixed team does not
break for one developer.

## With Go

```sh
go install github.com/ByteFinch-Technologies/secretveil/cmd/secretveil@latest
```

A binary installed this way reports its version as `dev`, because the version is stamped at
release time.

## From a release archive

Each release on GitHub carries an archive for each platform, a `checksums.txt` file, and a
bill of materials. Download the archive for your machine, then check it:

```sh
sha256sum --check --ignore-missing checksums.txt
```

The archives are signed with [cosign](https://docs.sigstore.dev/) and a short lived identity
from GitHub, so there is no private key to leak. To check the signature:

```sh
cosign verify-blob \
  --certificate secretveil_<version>_<platform>.tar.gz.pem \
  --signature secretveil_<version>_<platform>.tar.gz.sig \
  --certificate-identity-regexp 'https://github.com/ByteFinch-Technologies/secretveil/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  secretveil_<version>_<platform>.tar.gz
```

## Check the install

```sh
secretveil version
secretveil doctor
```

`doctor` writes nothing. It is safe to run in any project, at any time, before you decide
anything.

## When the install goes wrong

**`secretveil is installed but @secretveil/<platform> is not`**

npm skipped the platform package. This happens after an install with `--no-optional`, and
with a lock file that was made on a different platform. Install the platform package by hand,
or install again without `--no-optional`:

```sh
npm install @secretveil/darwin-arm64
```

**`secretveil has no binary for <platform>`**

The machine is one we do not build for yet. Build the program from source with the Go line
above, then name the result:

```sh
export SECRETVEIL_BINARY=/path/to/secretveil
```

**A Docker image or a CI runner with no npm cache**

Pin the version in `package.json` and commit the lock file. `npx secretveil@0.1.0` also
works, and it names the version in the log of every build.

## Remove it

`secretveil restore` gives back the original `.env` file, byte for byte, so the project is
exactly as it was before. Do that first, then remove the package:

```sh
secretveil restore
npm uninstall secretveil
rm -rf .secretveil
```

**Warning: after `restore`, your secrets are in the clear on disk again.**

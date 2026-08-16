# secretveil in CI

A build server has no keychain and no human at a terminal. It also must not hold the
encrypted store, because the store is in `.gitignore` and never reaches the repository.

So CI takes the values from the environment. Your CI platform already has a secret store, and
secretveil reads that one instead of its own.

## The rule

The variable name is the reference in upper case, with the prefix `SV_`.

| Handle in the file | Variable in CI |
|---|---|
| `sv://api_key` | `SV_API_KEY` |
| `sv://database_url_password` | `SV_DATABASE_URL_PASSWORD` |
| `sv://npmrc_registry_npmjs_org_authtoken` | `SV_NPMRC_REGISTRY_NPMJS_ORG_AUTHTOKEN` |

`secretveil list` prints every reference in the project, so you know exactly which variables
the build needs. `secretveil doctor` names any handle that has no value behind it.

Nothing else changes. The `.env` file in the repository holds the handles, `secretveil run`
resolves them, and the output filter works on the build log as well.

## GitHub Actions

```yaml
- run: npm ci

- name: build
  env:
    SV_API_KEY: ${{ secrets.SV_API_KEY }}
    SV_DATABASE_URL_PASSWORD: ${{ secrets.SV_DATABASE_URL_PASSWORD }}
    SECRETVEIL_CALLER: ci
  run: npx secretveil run -- npm run build
```

## GitLab CI

```yaml
build:
  variables:
    SECRETVEIL_CALLER: ci
  script:
    - npm ci
    - npx secretveil run -- npm run build
```

Add `SV_API_KEY` and its relatives as masked project variables. GitLab then keeps them out of
the log as well, which is a second filter on top of the one in `run`.

## Docker

Do not copy `.secretveil/` into the image. Pass the values at run time:

```sh
docker run --env SV_API_KEY="$SV_API_KEY" your-image \
  npx secretveil run -- node server.js
```

A value in a `docker build --build-arg` stays in the image history, so do not put a secret
there.

## The other two ways

The environment is the usual way. Two others exist for a machine that has to open the
encrypted store itself.

**`SECRETVEIL_IDENTITY`** holds an age identity, which is 74 characters. The store file has
to be on the machine as well. Use this when the build reads the same store as a developer.

**`SECRETVEIL_PASSPHRASE`** holds a passphrase. Use it on a headless Linux box with no
keyring. It is slower, because the key derivation takes about a second on purpose.

The program tries `SECRETVEIL_IDENTITY`, then `SECRETVEIL_PASSPHRASE`, then the keyring of
the operating system.

## Why `SECRETVEIL_CALLER=ci`

secretveil looks at its environment and decides whether the caller is a human, a build server
or an AI agent. An unknown caller is read as an agent, because the safe reading is the one
with the least power.

A build server has no terminal, which is also true of an agent. Set `SECRETVEIL_CALLER=ci` so
the decision is a fact and not a guess. It is recorded in the audit log either way.

`restore` and `get --reveal` need a human caller and are refused in CI. That is deliberate:
each of them writes a plaintext secret where something can read it.

## Use `doctor` as a gate

```sh
npx secretveil doctor
```

The exit code is 1 when a check found something that puts a secret at risk, such as a
plaintext secret still in a `.env` file. A note or a warning leaves the code at 0, so the gate
does not fail the build for advice.

This catches the common mistake: a developer adds a new secret to `.env`, forgets to run
`init`, and commits the plaintext value.

## What CI does not need

- No keychain.
- No `.secretveil/secrets.age`. Do not commit it to make CI work.
- No `init`. `init` is a step a developer runs once, by hand, with a terminal.

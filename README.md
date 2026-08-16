# secretveil

Let an AI coding agent work in your repository without letting it read your secrets.

Your `.env` file holds a handle instead of a value. The agent reads the file and learns the
name and the shape. It does not learn the secret. Your program still works, because
`secretveil run` puts the real value in the environment of the child process.

```
# before
API_KEY=sk-live-Q9xR2mVn7pLwT4aZ
DATABASE_URL=postgres://app:s3cr3t-p4ssw0rd-x9@db.internal:5432/app

# after
API_KEY=sv://api_key    # sv: 24 chars, base64, entropy 4.5
DATABASE_URL=postgres://app:sv://database_url_password@db.internal:5432/app
```

There is no plugin, no proxy and no integration with any AI tool. There is nothing to
integrate with, because the file on disk has no secret in it. Every AI tool is covered,
including one released after this was written.

An `.npmrc` is covered too. It cannot hold a handle, because npm reads the file itself and
would send the handle to the registry, so it holds a variable that npm expands instead:

```
# before
//registry.npmjs.org/:_authToken=npm_A9fK2xQw7ZtR4mVn8sLp3JhG1dYc5B

# after
//registry.npmjs.org/:_authToken=${SV_NPMRC_REGISTRY_NPMJS_ORG_AUTHTOKEN}
```

`secretveil run -- npm install` sets that variable and npm authenticates as it always did.
Without `secretveil run` the variable is unset, npm sends the literal text, and the registry
refuses it. Nothing leaks either way. The reasoning is in
[`docs/decisions.md`](docs/decisions.md), D7.

---

## Read this first: what it does NOT do

This section is above the feature list on purpose. A security tool that hides its limits is
worse than no tool, because you plan around a protection that is not there.

1. **A program that gets a value can leak it.** `secretveil run` gives the real value to the
   child process, because a program with a handle instead of a password cannot connect to
   the database. That program can write the value to a file. secretveil filters the output
   of the child process; it does not control what the child process writes to disk. An agent
   that can run any build script can get any secret. The adversarial test set asserts this
   theft **succeeds** (case 6), so it cannot be quietly lost in a later change.

2. **The command rules read a name, not a program.** An agent may not run `bash -c printenv`
   or `node -e '...'`. It may run `npm run build`, and that script can hold `printenv`. The
   rules block the cheapest attack. They are not a sandbox.

3. **Installing this does not rotate anything.** If your `.env` already went into a git
   history, a CI log, or an agent transcript, those values are compromised now. **Rotate
   first, install second.**

4. **A very short secret is not filtered.** A four character password appears in ordinary
   text, and removing every four character run would destroy the output. `run` names each
   value it skipped. Use a longer value.

5. **The agent still learns the shape.** The comment says the length, the character set and
   the entropy. That is deliberate, so the agent writes correct code against the variable.
   It is not nothing. Do not store a low entropy secret and expect the comment to hide it.

6. **It rewrites `.env` and `.npmrc`, and no other credential file.** A `.netrc` cannot be
   fixed at all, because curl, git and ftp read it literally and expand no variable. A
   `.yarnrc.yml`, a `.pypirc`, an `aws/credentials` and their relatives are not rewritten
   either. `secretveil doctor` finds these files, names the line, and says plainly that it
   cannot protect them. It never reports a clean project on the strength of files it did not
   open.

The full reasoning, and what the tool does stop, is in [`docs/threat-model.md`](docs/threat-model.md).

---

## What it does do

- **Removes the passive read.** The common leak is not an attack. It is an agent reading
  `.env` because reading files is what it does all day. After `init` there is nothing in
  that file to read.
- **Filters the output of your build.** A value that reaches standard output or standard
  error is replaced with its handle first. This catches the stack trace that prints a
  connection string and the debug line that dumps a config object. The filter works across
  chunk boundaries and matches the base64 form of each value.
- **Refuses the cheap environment dump.** `bash -c printenv`, `node -e 'console.log(process.env)'`
  and their relatives are refused for an agent caller, and the refusal is logged. A path in
  front of the name does not help.
- **Keeps a local audit log.** Every run, refusal and reveal is recorded in the project. The
  log never holds a value, and command lines are redacted before they are written.
- **Gives back your original file, byte for byte.** `secretveil restore` undoes `init`
  exactly. This is a release gate, tested on every fixture repository.

---

## Install

```sh
go install github.com/ByteFinch-Technologies/secretveil/cmd/secretveil@latest
```

**While this repository is private, that line fails on its own.** The public checksum database
cannot read a private repository, so the command stops with a 404 from `sum.golang.org`. Tell the
Go tool to skip the public database for this path:

```sh
export GOPRIVATE='github.com/ByteFinch-Technologies/*'
go install github.com/ByteFinch-Technologies/secretveil/cmd/secretveil@latest
```

You also need git access to the repository. A binary installed this way reports its version as
`dev`, because the version is stamped at release time. Delete this note when the repository
becomes public.

## Use it

```sh
cd your-project

secretveil plan        # show what would change. Writes nothing.
secretveil init        # move the secrets into the store, put handles in the files
secretveil doctor      # check the setup and say what to fix
```

Then put `secretveil run --` in front of the command that needs the values:

```sh
secretveil run -- npm run dev
secretveil run -- python manage.py runserver
secretveil run -- go test ./...
```

Nothing in your application changes. dotenv, Vite and Next.js all give a variable in the
environment priority over the same variable in a `.env` file, so your framework loads the
real value exactly the way it always did. The measurement is recorded as D4 in
[`docs/decisions.md`](docs/decisions.md).

### More than one `.env` file

`init` moves the secrets out of every `.env` file it finds, so `.env.development`,
`.env.staging` and `.env.production` all get handles too.

`run` reads two of those files on its own: `.env` and `.env.local`. Those two names mean the
same thing in every framework. `.env.production` does not, because Next.js loads it for
`NODE_ENV=production` and Vite loads it for mode `production`, which is a different question.
secretveil does not guess. Name the files you want, in load order:

```sh
secretveil run --env-file .env --env-file .env.development --env-file .env.local -- npm run dev
```

A later file wins over an earlier one, which is the order every framework holds. Put `.env`
first and `.env.local` last.

You do not have to work this out. `init` prints the whole command when it rewrote a file
outside the two default names, and `doctor` names any such file and prints the same command:

```
!  1 .env file(s) hold a handle that run does not resolve
   .env.development: init rewrote this file, but run does not read it
   Your framework reads the file itself and gives the program the handle text.
   Name the files you want, in load order. A later file wins over an earlier one:
     secretveil run --env-file .env --env-file .env.development -- <command>
```

The decision is recorded as D8 in [`docs/decisions.md`](docs/decisions.md).

### Node projects with a private registry

`init` reads every `.npmrc` under the project, not only the one at the top, so a workspace
gets the same treatment as the root. Put `secretveil run --` in front of any command that
talks to the registry:

```sh
secretveil run -- npm install
secretveil run -- npm publish
```

Only a registry credential is rewritten: `_authToken`, `_auth` and `_password`. A registry
address, a scope mapping and every other setting stay exactly as they are, because npm has to
read them. A value in quotes is left alone as well, because npm and this tool do not agree on
what a quoted value means, and a wrong guess would put the wrong bytes in your file.

### Every command

| Command | What it does |
|---|---|
| `plan` | Show what `init` would change. Writes nothing. |
| `init` | Move every secret into the store and put a handle in its place. |
| `run -- <cmd>` | Run a program with the real values, and filter them out of its output. |
| `doctor` | Check the setup of the project and say what to fix. |
| `restore` | Put the plaintext values back. Gives the original file byte for byte. Needs a human caller. |
| `set <ref>` | Put one secret in the store. |
| `list` | Print the name of every secret in the store. |
| `get <ref>` | Print one plaintext value. Needs `--reveal` and a human caller. |
| `rm <ref>` | Remove one secret from the store. |

`set` never takes the value from the command line, because every user on the machine can
read the arguments of a running program and the shell keeps them in its history. It reads
from a hidden terminal prompt, from standard input, or from `--from-file`.

---

## How it decides what is a secret

`plan` and `init` classify each variable into one of three classes.

| Class | Meaning | Example |
|---|---|---|
| open | Not a secret. Left alone. | `NODE_ENV=development` |
| partial | A composite value. The readable part stays. | `postgres://app:sv://db_password@db:5432/app` |
| veiled | The whole value goes into the store. | `API_KEY=sv://api_key` |

Partial disclosure matters more than it looks. An agent that can see the host, the user and
the database name of a connection string can write and debug code against it. One that sees
only `sv://database_url` cannot.

Run `secretveil plan` and read the table before you run `init`. The default output never
prints a value.

---

## Where the secrets live

One encrypted file, `.secretveil/secrets.age`, in the [age](https://age-encryption.org)
format. The key that opens it is a 74 character age identity, held in your operating system
keyring.

The keyring holds the identity and never a secret value. On macOS the keychain silently cuts
a value at 128 bytes when it is written through the standard input path, and the command
line path puts the plaintext where every user on the machine can read it with `ps`. Holding
one short identity avoids both, and it is what makes a multi-line value such as a PEM
private key work. See D1 in [`docs/decisions.md`](docs/decisions.md).

On a machine with no keyring, set `SECRETVEIL_PASSPHRASE`.

`init` adds `.secretveil/` to `.gitignore`. `doctor` checks that it is still there.

---

## Who is calling

Three kinds of caller get different powers.

| Caller | How it is recognised | What it may do |
|---|---|---|
| Human | Standard input and standard output are both a terminal | Everything |
| CI | A pipeline marker such as `GITHUB_ACTIONS` is set | Everything. The filter still runs |
| Agent | A marker such as `CLAUDECODE` is set, **or nothing matched** | No shell, no inline code, no reveal, no restore |

**An unknown caller is treated as an agent.** A command with no terminal and no marker could
be a script you wrote, or a tool nobody has heard of yet. The safe reading is the one with
the least power.

Set `SECRETVEIL_CALLER=human` when that is wrong. Edit `.secretveil/policy.toml` to change
what an agent may run, or set `enforce = false` to turn the command rules off and keep the
output filter.

---

## Environment variables

| Name | What it is for |
|---|---|
| `SECRETVEIL_CALLER` | `human`, `ci` or `agent`. Overrides the detection rules. |
| `SECRETVEIL_IDENTITY` | An age identity that opens the store. For CI. |
| `SECRETVEIL_PASSPHRASE` | A passphrase that opens the store, for a machine with no keyring. |

---

## Documentation

- [`docs/threat-model.md`](docs/threat-model.md) — what is stopped, what is not, and why.
- [`docs/decisions.md`](docs/decisions.md) — each decision that changed the plan, with the
  measurement that caused it.
- [`SECURITY.md`](SECURITY.md) — how to report a problem.

## Licence

Apache 2.0. See [`LICENSE`](LICENSE).

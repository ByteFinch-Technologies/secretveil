<div align="center">
  <h1>secretveil</h1>
  <p align="center">
    <b>Let an AI coding agent work in your repository without letting it read your secrets.</b><br>
    Your <code>.env</code> file holds a handle. The real value never touches the disk in plaintext.
  </p>
  <p align="center">
    <a href="https://github.com/ByteFinch-Technologies/secretveil/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/ByteFinch-Technologies/secretveil/actions/workflows/ci.yml/badge.svg"></a>
    <a href="https://github.com/ByteFinch-Technologies/secretveil/actions/workflows/codeql.yml"><img alt="CodeQL" src="https://github.com/ByteFinch-Technologies/secretveil/actions/workflows/codeql.yml/badge.svg"></a>
    <a href="https://www.npmjs.com/package/secretveil"><img alt="npm" src="https://img.shields.io/npm/v/secretveil?color=cb3837&logo=npm&logoColor=white"></a>
    <a href="https://pkg.go.dev/github.com/ByteFinch-Technologies/secretveil"><img alt="Go Reference" src="https://pkg.go.dev/badge/github.com/ByteFinch-Technologies/secretveil.svg"></a>
    <a href="https://goreportcard.com/report/github.com/ByteFinch-Technologies/secretveil"><img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/ByteFinch-Technologies/secretveil"></a>
    <a href="LICENSE"><img alt="Licence" src="https://img.shields.io/badge/licence-Apache%202.0-blue.svg"></a>
  </p>
  <p align="center">
    <a href="#highlights">Highlights</a> •
    <a href="#the-limits-read-this-before-you-rely-on-it">Limits</a> •
    <a href="#quickstart">Quickstart</a> •
    <a href="#install">Install</a> •
    <a href="#commands">Commands</a> •
    <a href="#how-it-works">How it works</a> •
    <a href="docs/README.md">Docs</a>
  </p>
</div>

---

An AI coding agent reads your files. That is the job. One of those files is `.env`, and it
holds the key to your payment provider, your database and your mail server. secretveil takes
the value out of that file and puts a handle in its place. The agent reads the file and learns
the name and the shape. It does not learn the secret. Your program still works, because
`secretveil run` puts the real value in the environment of the child process.

```diff
- API_KEY=sk-live-Q9xR2mVn7pLwT4aZ
- DATABASE_URL=postgres://app:s3cr3t-p4ssw0rd-x9@db.internal:5432/app
+ API_KEY=sv://api_key    # sv: 24 chars, base64, entropy 4.5
+ DATABASE_URL=postgres://app:sv://database_url_password@db.internal:5432/app
```

Read the second line again. Only the password moved. The host, the port and the database name
stay readable, so the agent can still write and debug code against that connection.

There is no plugin, no proxy and no integration with any AI tool. There is nothing to integrate
with, because the file on disk has no secret in it. Every AI tool is covered, including one
released after this was written.

> **Are you an AI agent, or do you want one to install this?** Read
> [`docs/for-agents.md`](docs/for-agents.md). It is the same setup, written as instructions an
> agent can follow without touching a plaintext value.

## Highlights

- **Nothing to integrate.** No plugin and no proxy. The protection is the file itself.
- **Removes the passive read.** The common leak is not an attack. It is an agent that reads
  `.env` because it reads files all day. After `init` there is nothing in that file to read.
- **Keeps the readable part.** A connection string loses its password and keeps its host. Your
  agent stays useful.
- **Filters the output of your build.** A value that reaches standard output or standard error
  is replaced with its handle first. This catches the stack trace that prints a connection
  string. The filter works across chunk boundaries and matches the encoded forms,
  which are base64 in both alphabets, hex, the URL escape and the JSON string escape.
- **Refuses the cheap environment dump.** `bash -c printenv` and its relatives are refused for
  an agent caller, and the refusal goes into a local audit log that never holds a value.
- **Reversible, byte for byte.** `secretveil restore` undoes `init` exactly. The test
  `TestInitThenRestoreGivesBackTheSameBytes` holds that promise, and CI runs it on every commit.
- **Local and account free.** One encrypted file in your project and one key in your operating
  system keyring. There is no service to sign up to and no network call.

## The limits: read this before you rely on it

This section is above the install instructions on purpose. A security tool that hides its
limits is worse than no tool, because you plan around a protection that is not there.

1. **A program that gets a value can leak it.** `secretveil run` gives the real value to the
   child process, because a program with a handle instead of a password cannot connect to the
   database. That program can write the value to a file. An agent that can run any build script
   can get any secret. The adversarial test set asserts this theft **succeeds** (case 6), so it
   cannot be quietly lost in a later change.

2. **The command rules read a name, not a program.** An agent may not run `bash -c printenv` or
   `node -e '...'`. It may run `npm run build`, and that script can hold `printenv`. The rules
   block the cheapest attack. They are not a sandbox.

3. **Installing this does not rotate anything.** If your `.env` already went into a git history,
   a CI log, or an agent transcript, those values are compromised now. **Rotate first, install
   second.**

4. **A very short secret is not filtered.** A four character password appears in ordinary text,
   and removal of every four character run would destroy the output. `run` names each value it
   skipped. Use a longer value.

5. **The agent still learns the shape.** The comment says the length, the character set and the
   entropy. That is deliberate, so the agent writes correct code against the variable. Do not
   store a low entropy secret and expect the comment to hide it.

6. **It rewrites `.env` and `.npmrc`, and no other credential file.** A `.netrc` cannot be fixed
   at all, because curl, git and ftp read it literally and expand no variable. A `.yarnrc.yml`,
   a `.pypirc`, an `aws/credentials` and their relatives are not rewritten either. `doctor`
   finds these files, names the line, and says plainly that it cannot protect them. It never
   reports a clean project on the strength of files it did not open.

The full reasoning, and what the tool does stop, is in
[`docs/threat-model.md`](docs/threat-model.md).

## Quickstart

Four steps, and the first one installs nothing.

### 1. Look first. It writes nothing.

```sh
cd your-project
npx secretveil plan
```

`plan` prints one line for each variable: the key, whether it is a secret, and the shape of the
value. It never prints a value. Read the table before you go on.

### 2. Move the secrets out of the file.

```sh
npx secretveil init
```

Your `.env` changes from this:

```sh
API_KEY=sk-live-Q9xR2mVn7pLwT4aZ
DATABASE_URL=postgres://app:hunter2@db.host:5432/prod
NODE_ENV=development
```

to this:

```sh
API_KEY=sv://api_key            # sv: 24 chars, base64, entropy 4.5
DATABASE_URL=postgres://app:sv://database_url_password@db.host:5432/prod
NODE_ENV=development
```

Read what stayed. `NODE_ENV` is not a secret, so it is untouched. In the database URL only the
password moved.

The real values go into one encrypted file, `.secretveil/secrets.age`. The key that opens that
file lives in the keyring of your operating system, not in the project. `init` adds
`.secretveil/` to `.gitignore` for you.

### 3. Put `secretveil run --` in front of your command.

```sh
npx secretveil run -- npm run dev
npx secretveil run -- python manage.py runserver
npx secretveil run -- go test ./...
```

Your code does not change. Keep dotenv, Next.js or Vite exactly as they are. `run` puts the real
values in the environment of the child process, and every one of those loaders gives a variable
in the environment priority over the same variable in a file. The measurement is D4 in
[`docs/decisions.md`](docs/decisions.md).

Put it in `package.json`, so that nobody has to remember it:

```json
{
  "scripts": {
    "dev": "secretveil run -- next dev",
    "test": "secretveil run -- vitest"
  }
}
```

Then `npm run dev` works as it did before.

### 4. Check the setup.

```sh
npx secretveil doctor
```

`doctor` names anything that will surprise you later: a handle with no value behind it, a
plaintext secret still in a file, or a credential in a file that secretveil cannot rewrite.

To undo all of it, run `secretveil restore`. It gives back your original file byte for byte.

## Install

`npx` needs no install and is the fastest way to try it:

```sh
npx secretveil doctor              # run it once, install nothing
```

Install it properly when you decide to keep it:

```sh
npm install --save-dev secretveil  # one project, one version for the team
npm install --global secretveil    # every project on this machine
```

The npm package holds no binary. It names four platform packages, and npm installs only the one
that matches the machine.

| Platform | Intel | ARM |
|---|---|---|
| macOS | ✅ | ✅ |
| Linux | ✅ | ✅ |
| Windows | planned for v0.3 | planned for v0.3 |

A Go developer may build from source instead:

```sh
go install github.com/ByteFinch-Technologies/secretveil/cmd/secretveil@latest
```

Each release also carries a signed archive for each platform, with a checksum and a bill of
materials. [`docs/install.md`](docs/install.md) has the archive, the signature check, and what to
do when an install goes wrong.

## Everyday use

### Share it with a teammate

A teammate pulls the `.env` with the handles from git. The store never goes into git, so they
supply each value once:

```sh
secretveil list                # the names, never the values
secretveil set api_key         # a hidden prompt
```

`set` never takes the value from the command line, because every user on the machine can read
the arguments of a running program and the shell keeps them in its history. It reads from a
hidden terminal prompt, from standard input, or from `--from-file`.

### More than one `.env` file

`init` moves the secrets out of every `.env` file it finds, so `.env.development`, `.env.staging`
and `.env.production` all get handles too.

`run` reads two of those files on its own: `.env` and `.env.local`. Those two names mean the same
thing in every framework. `.env.production` does not, because Next.js loads it for
`NODE_ENV=production` and Vite loads it for mode `production`, which is a different question.
secretveil does not guess. Name the files you want, in load order, and a later file wins:

```sh
secretveil run --env-file .env --env-file .env.development -- npm run dev
```

You do not have to work this out. `init` prints the whole command when it rewrote a file outside
the two default names, and `doctor` prints the same command. The decision is D8 in
[`docs/decisions.md`](docs/decisions.md).

### A private npm registry

An `.npmrc` cannot hold a handle, because npm reads the file itself and would send the handle to
the registry. It holds a variable that npm expands instead:

```diff
- //registry.npmjs.org/:_authToken=npm_A9fK2xQw7ZtR4mVn8sLp3JhG1dYc5B
+ //registry.npmjs.org/:_authToken=${SV_NPMRC_REGISTRY_NPMJS_ORG_AUTHTOKEN}
```

`secretveil run -- npm install` sets that variable and npm authenticates as it always did.
Without `run` the variable is unset, npm sends the literal text, and the registry refuses it.
Nothing leaks either way.

`init` reads every `.npmrc` under the project, so a workspace gets the same treatment as the
root. Only a registry credential is rewritten: `_authToken`, `_auth` and `_password`. Every other
setting stays as it is, because npm has to read it. A value in quotes is left alone as well,
because npm and this tool do not agree on what a quoted value means. The reasoning is D7 in
[`docs/decisions.md`](docs/decisions.md).

### On a build server

A build server has no keychain and no human at a terminal. Set `SECRETVEIL_PASSPHRASE`, or supply
the identity directly. [`docs/ci.md`](docs/ci.md) has a working job for GitHub Actions and the
equivalent for other runners.

## Commands

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
| `version` | Print the version. |
| `completion <shell>` | Print the autocompletion script for bash, zsh, fish or PowerShell. |

Every flag is in [`docs/commands.md`](docs/commands.md).

## How it works

### What counts as a secret

`plan` and `init` put each variable in one of three classes.

| Class | Meaning | Example |
|---|---|---|
| open | Not a secret. Left alone. | `NODE_ENV=development` |
| partial | A composite value. The readable part stays. | `postgres://app:sv://db_password@db:5432/app` |
| veiled | The whole value goes into the store. | `API_KEY=sv://api_key` |

Partial disclosure matters more than it looks. An agent that can see the host, the user and the
database name of a connection string can write and debug code against it. One that sees only
`sv://database_url` cannot.

### Where the values live

One encrypted file, `.secretveil/secrets.age`, in the [age](https://age-encryption.org) format.
The key that opens it is a 74 character age identity, held in the keyring of your operating
system. The keyring holds the identity and never a secret value, which is what makes a multi-line
value such as a PEM private key work. The measurements behind that choice are D1 in
[`docs/decisions.md`](docs/decisions.md).

On a machine with no keyring, set `SECRETVEIL_PASSPHRASE`.

`init` adds `.secretveil/` to `.gitignore`. `doctor` checks that it is still there.

### Who is calling

Three kinds of caller get different powers.

| Caller | How it is recognised | What it may do |
|---|---|---|
| Human | Standard input and standard output are both a terminal | Everything |
| CI | A pipeline marker such as `GITHUB_ACTIONS` is set | Everything. The filter still runs |
| Agent | A marker such as `CLAUDECODE` is set, **or nothing matched** | No shell, no inline code, no reveal, no restore |

**An unknown caller is treated as an agent.** A command with no terminal and no marker could be a
script you wrote, or a tool nobody has heard of yet. The safe reading is the one with the least
power.

Set `SECRETVEIL_CALLER=human` when that is wrong. Edit `.secretveil/policy.toml` to change what an
agent may run, or set `enforce = false` to turn the command rules off and keep the output filter.

## Related tools

secretveil solves one narrow problem: what an AI coding agent sees when it reads your project.
Several good tools sit near it and answer a different question.

| Tool | What it is for |
|---|---|
| [dotenvx](https://github.com/dotenvx/dotenvx) | Encrypts each value inside `.env`, so the file holds ciphertext. The private key sits in `.env.keys` or a cloud manager. |
| [SOPS](https://github.com/getsops/sops) | Encrypts a whole configuration file so that the file itself is safe to commit to git. |
| [git-crypt](https://github.com/AGWA/git-crypt) | Encrypts chosen files at the git boundary. The working copy stays plaintext. |
| 1Password CLI, Doppler, Infisical, Vault | A hosted vault plus a `run` command. The file holds a reference and the value comes over the network. |

Three things are different here. secretveil is local and needs no account and no network call. It
keeps the readable part of a composite value, so the agent stays useful instead of blind. And it
treats the caller as untrusted by default, which is why the output filter and the command rules
exist at all.

Pick the tool that matches your threat. They also combine: an encrypted file in git and a veiled
file on the workstation answer different halves of the same worry.

## Documentation

Everything is in [`docs/`](docs/README.md).

| Page | Read it when |
|---|---|
| [`docs/for-agents.md`](docs/for-agents.md) | An AI agent installs or operates this. |
| [`docs/install.md`](docs/install.md) | You need npm, Go, a signed archive, or a broken install. |
| [`docs/commands.md`](docs/commands.md) | You want every command and every flag. |
| [`docs/ci.md`](docs/ci.md) | The build server has no keychain and no human. |
| [`docs/faq.md`](docs/faq.md) | Something surprised you on day two. |
| [`docs/threat-model.md`](docs/threat-model.md) | You are deciding whether to rely on this. |
| [`docs/decisions.md`](docs/decisions.md) | You want the measurement behind a decision. |
| [`SECURITY.md`](SECURITY.md) | You have a problem to report. |

## Contributing

Issues and pull requests are welcome at
[the issue tracker](https://github.com/ByteFinch-Technologies/secretveil/issues).

Two rules govern a change to this repository:

1. **A plaintext escape that is not a documented limit is a bug, not a feature request.** Report
   it through [`SECURITY.md`](SECURITY.md) and not through a public issue.
2. **No test may hold a real credential.** Every fixture value in this repository is synthetic,
   and a test asserts it.

Run `go test ./...` and `go vet ./...` before you open a pull request. CI runs the same checks,
plus five fuzz targets and four suites that assert the security promises:

- an agent cannot escape (`test/adversarial/`)
- the binary cannot reach a network (`test/nonetwork/`)
- no value survives the filter (`test/leak/`)
- no file holds a credential-shaped value (`test/hygiene/`)

## Security

Email **security@bytefinch.dev**. Do not open a public issue for a vulnerability. You get a reply
within 3 working days. [`SECURITY.md`](SECURITY.md) says what counts as a vulnerability, and lists
the documented limits that are already known.

Each release is signed. [`docs/install.md`](docs/install.md) has the command that verifies the
archive, the checksum and the bill of materials.

## Licence

Apache 2.0. See [`LICENSE`](LICENSE).

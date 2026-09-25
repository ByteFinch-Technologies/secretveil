# Command reference

Every command accepts `--help`. The text there is the same text as here, and it is generated
from the program, so it is never out of date.

| Command | What it does | Writes |
|---|---|---|
| [`plan`](#plan) | Show what `init` would do. | nothing |
| [`init`](#init) | Move every secret into the store, put a handle in its place. | files, store |
| [`run`](#run) | Run a program with the real values, and filter them out of its output. | nothing |
| [`doctor`](#doctor) | Check the project and say what to fix. | nothing |
| [`restore`](#restore) | Put the plaintext values back. | files |
| [`set`](#set) | Put one secret in the store. | store |
| [`get`](#get) | Print one plaintext value. | nothing |
| [`list`](#list) | Print the name of every secret in the store. | nothing |
| [`rm`](#rm) | Remove one secret from the store. | store |
| `version` | Print the version. | nothing |
| [`completion`](#completion) | Print the shell autocompletion script. | nothing |

Each command that takes a path takes it as the first argument, and uses the current directory
when you give none. The project is the first directory at or above that path that holds a
marker such as `package.json`, `go.mod` or `.git`.

---

## plan

```sh
secretveil plan [path] [flags]
```

Finds every `.env` file, classifies every variable, and prints the result. It writes nothing
and changes nothing, so it is safe to run at any time.

| Flag | What it does |
|---|---|
| `--json` | Print the plan as JSON. |
| `--projection` | Print each file as the agent would read it. |

The default output never prints a value. It prints the key, the class, the rule that fired
and the shape. `--projection` is safe as well, because every secret in that output is already
replaced by a handle.

---

## init

```sh
secretveil init [path] [flags]
```

Reads each value, decides whether the value is a secret, writes the secret into the encrypted
store, and puts a handle such as `sv://api_key` in the file.

| Flag | What it does |
|---|---|
| `--dry-run` | Show the plan and write nothing. |
| `-y, --yes` | Do not ask for confirmation. |
| `--no-ignore` | Do not add `.secretveil/` to `.gitignore`. |
| `--keep-backup` | Leave the plaintext backup on disk. Do not use it. |
| `-v, --verbose` | Print one line for each step. |

`init` is safe to stop. Each step can be undone, and a failure in any step puts every file
back the way it was.

Two files that hold the same key make a name collision. `init` renames the second one after
the file it came from, so `.env.development` gives `env_development_api_key`, and it prints
each rename it made.

One file that names the same key twice is the same case. A loader reads the last assignment,
so the first one is dead text, but it still holds whatever the developer put there. `init`
gives each record its own name and rewrites both, so no value stays in the file. Two records
that hold the same value keep one name, because one name for one value is correct.

A second `init` never replaces a value that is already in the store. A new file that holds a
different value under a name the store already has gets a new name, in the same way. The same
value under the same name keeps the name.

`init` needs an answer at the prompt. A command with no terminal and no `--yes` stops,
because `init` rewrites files in the project and a tool that runs it without a human behind
it must say so with the flag.

---

## run

```sh
secretveil run [flags] -- <command> [args...]
```

Does three things:

1. Reads the `.env` files, replaces every `sv://` handle with the real value, and puts the
   result in the environment of the program.
2. Gives the program a terminal, so colour, progress bars and a password prompt all still
   work.
3. Reads every byte the program prints and removes every secret from it.

| Flag | Default | What it does |
|---|---|---|
| `--env-file` | `.env` and `.env.local` | The `.env` files to read, in load order. |
| `--dir` | the current one | The working directory of the program. |
| `--allow-missing` | off | Start even when the store holds no value for a handle. If the store does not open, `run` still starts and prints one warning that names the fault, also with `-q`. |
| `--no-pty` | off | Use pipes, so standard output and standard error stay apart. |
| `--pty` | off | Use a terminal even when the output is a file or a pipe. |
| `--idle-flush` | 40ms | How long the filter waits before it releases the bytes it holds. |
| `-q, --quiet` | off | Print nothing of our own. |

Give `--env-file` once for each file, in load order. A later file wins over an earlier one:

```sh
secretveil run --env-file .env --env-file .env.development -- npm run dev
```

A variable that the environment of `run` already holds wins over the same name in a file, and
`run` says so. There is one exception: a value that holds a handle, such as the `sv://api_key`
that direnv loads from `.env`. That text is not a value, so the file wins and `run` replaces
the handle.

The exit code of `run` is the exit code of the program, so it works in a pipeline and in a
`Makefile` exactly as the program did.

**Why the filter holds bytes.** A secret can be split across two writes. The filter keeps a
small window of bytes until it knows the window holds no secret. `--idle-flush` is how long
it waits when the program goes quiet, so a prompt that has no newline still appears. Raise it
if a partial line appears late; lower it for a program that prints a live progress bar.

---

## doctor

```sh
secretveil doctor [path]
```

Reports anything that would surprise you later. It writes nothing and changes nothing.

It checks that the store opens on this machine, that every reference in your `.env` and
`.npmrc` files has a value behind it, that no plaintext secret is left in a file, that
`.gitignore` covers the store, that the policy file loads, and that `run` reads every `.env`
file that holds a handle.

It also names a credential in a file that secretveil does not rewrite, such as `.netrc` or
`.yarnrc.yml`. It cannot protect those files, and it says so rather than report a clean
project.

The exit code is 0 when nothing is wrong, and 1 when a check found something that puts a
secret at risk. A note or a warning does not change the exit code, so `doctor` is safe as a
gate in CI.

---

## restore

```sh
secretveil restore [path] [flags]
```

The exact opposite of `init`. It reads every handle in every `.env` file, asks the store for
the value, and writes the value in place of the handle. The result is the original file, byte
for byte.

| Flag | What it does |
|---|---|
| `--dry-run` | Show what would change and write nothing. |
| `-y, --yes` | Do not ask for confirmation. |

`restore` needs no backup. The file with the handles and the store together hold everything
the original file held. It stops before it writes anything if the store cannot supply every
value, because a file that is half restored is worse than a file that is not restored.

`restore` needs a human caller. An AI agent that could run it would need one command to undo
the whole tool.

**Warning: after `restore`, your secrets are in the clear on disk again.**

---

## set

```sh
secretveil set <ref> [flags]
```

Writes one value into the encrypted store, under the reference you give.

| Flag | What it does |
|---|---|
| `--from-file` | Read the value from a file. Use `-` for standard input. |
| `--raw` | Keep every byte, including a newline at the end. |

The value never comes from the command line. Every user on the machine can read the arguments
of a running program, and the shell keeps them in its history file. So `set` reads the value
from the terminal with no echo, from standard input, or from a file.

A newline at the end is removed, because a pasted value nearly always carries one and almost
no secret needs one.

After `set`, put the handle in the `.env` file by hand:

```
API_KEY=sv://api_key
```

An AI agent may add a new reference. To replace a value that is already in the store needs a
human caller, because a new value can send a program to a host that the agent controls. Each
write goes into the audit log, with the reference and never the value.

---

## get

```sh
secretveil get <ref> --reveal
```

Prints one plaintext value on standard output. This command undoes everything the rest of the
tool does, so it asks for two things: the `--reveal` flag, and a human caller.

Use it when you must copy a value into a dashboard by hand. Do not use it in a script and do
not use it in a pipeline. Use `secretveil run` there, which gives the value to the program and
keeps it out of the output.

---

## list

```sh
secretveil list
```

Prints the reference of every secret in the store of this project. It prints no values, so it
is safe to run in front of anyone.

---

## rm

```sh
secretveil rm <ref>
```

Removes one secret from the store. Run `doctor` after it: a handle left in a file with no
value behind it is exactly what `doctor` reports.

The value is gone for good, so `rm` needs a human caller, the same as `get --reveal`. A
refusal and each removal go into the audit log.

---

## policy approve

```sh
secretveil policy approve
```

Records that a human wrote `.secretveil/policy.toml`. Needs a human caller.

The policy file sits inside the project, and an agent writes files there all day. So a file
that turns off a default rule does not apply to an agent until a human approves it. Examples:
`enforce = false`, a deny list without `sh`, or an `inline_code` rule without `-e` for `node`.
Until then, an agent gets the default rules as well as the rules in the file. A file that only
adds rules needs no approval.

`approve` stores the SHA-256 of the file inside the encrypted store, with the modification time
of the file and, on Unix, its inode and its change time. It also writes a `policy` record to the
audit log. A change to the file cancels the approval, so run it again after each change. The
approval names one copy of the file on disk, so these also cancel it, even when the bytes stay
the same:

- a save from an editor, a `touch`, or a `chmod`
- a move or a hard link of the file, away and back
- a file that is removed and written back
- a copy of the project to a new directory

When an agent runs a command and the stored approval does not name the file, secretveil removes
the approval. `doctor` says whether the file needs an approval.

When the file allows a command and the default rules refuse it, the refusal names the missing
approval, so you can see why the file did not apply.

---

## completion

```sh
secretveil completion bash|zsh|fish|powershell
```

Prints an autocompletion script for the shell you name. The command prints the script and
writes nothing, so send the output to the place your shell reads. For zsh:

```sh
secretveil completion zsh > "${fpath[1]}/_secretveil"
```

Run `secretveil completion <shell> --help` for the path that your shell wants.

---

## Environment variables

| Name | What it is for |
|---|---|
| `SECRETVEIL_CALLER` | `human`, `ci` or `agent`. Overrides the detection rules, except that the marker of an AI tool always wins. |
| `SECRETVEIL_IDENTITY` | An age identity that opens the store. For CI. |
| `SECRETVEIL_PASSPHRASE` | A passphrase that opens the store, for a machine with no keyring. |
| `SECRETVEIL_BINARY` | The path of the binary, for the npm package on a platform we do not build for. |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | The command did what it was asked. |
| 1 | The command failed, or `doctor` found something that puts a secret at risk. |
| any | `run` returns the exit code of the program it ran. |

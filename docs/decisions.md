# Decisions

This file records a decision that changed the implementation plan. Each entry gives the
measurement or the reason that caused the change.

---

## D1. The keyring holds the file key, not the secrets

**Date:** 2026-08-15
**Changes:** section 3.7 of `IMPLEMENTATION-PLAN.md`, which listed `keychain` as a general
backend that holds each secret value.

**Measurement.** The macOS `security` command has two ways to write a value.

| Path | Result | Measured |
|---|---|---|
| Standard input, through the prompt | The value is cut at 128 bytes. Exit code 0. No message. | A 129 byte value came back as 128 bytes. A 4000 byte value came back as 128 bytes. |
| The command line, with `-w <value>` | The value survives at 4000 bytes. | Every user on the machine can read it with `ps`. |

Both paths are unsafe for a secret. The first loses data without a warning. The second puts
the plaintext in the process list.

**Decision.** The operating system keyring holds one short string for each project: an age
identity, which is 74 characters. Every secret value lives in one encrypted file. The
`keyring` package refuses any value over 128 bytes, refuses a line break, and reads the
value back after each write to prove the backend did not change it.

**Effect.** A multi-line value, such as a PEM private key, works. It could not work through
the keyring. The `agefile` backend is now the only writable store on a workstation.

---

## D2. The encrypted file uses the age format

**Date:** 2026-08-15

**Reason.** A secrets tool must not carry a new file format written for it. The age format
has a published specification and a reviewed Go implementation. It also supports several
recipients for one file, which flow C in `PRODUCT-SPEC.md` needs when a team shares a store.

**Cost.** One dependency, `filippo.io/age`.

**Key sources, in order.** The program tries each one and uses the first that works.

1. `SECRETVEIL_IDENTITY`, an age identity. This is the continuous integration path.
2. `SECRETVEIL_PASSPHRASE`. This is the headless machine path, where there is no keyring.
3. The operating system keyring. This is the workstation path. The program makes the
   identity on first use.

The age format refuses a passphrase identity next to any other identity, so the program
tries one source at a time and remembers which one opened the file. A later write uses the
same source, so a read and a write never disagree about the key.

---

## D3. `envstore` reports unavailable when the environment is empty

**Date:** 2026-08-15

**Reason.** `envstore` sits first in the chain, because a value set by a continuous
integration job must beat the file. If an empty environment reported itself as available,
every lookup would still pass through it, and a missing variable would read as a missing
secret. The backend now reports available only when at least one `SV_` variable is set.

---

## D4. dotenv, Vite and Next.js all give priority to the environment

**Date:** 2026-08-14

**Measurement.** A test with dotenv 17.4.2 set `MY_VAL` in the process environment and also
in the `.env` file. The value from the environment survived. The file did not overwrite it.
dotenv reported "injected env (1)", which counts only the variable that was not already set.

**Effect.** This is the property that makes the whole product work. `secretveil run` puts
the real value in the environment of the child process, and the handle in the `.env` file is
never read, because the loader keeps the value that is already there. No change to the
application is needed.

---

## D5. An idle flush may split one placeholder into two

**Date:** 2026-08-15

**Measurement.** One needle `aa` and the input `0aaaaa`. In one write the filter writes four
placeholders. With an idle flush after `0aaa` it writes three. No byte of the input reaches
the output in either case.

**Reason.** While the stream is quiet, `idleLimit` releases a run of bytes that a needle
already covers, so a prompt that ends with a secret still reaches the terminal instead of
waiting for input that never comes. A run that is already complete can still grow when the
next byte arrives, and the part that is already out cannot be taken back. The filter writes a
second placeholder beside the first.

**Effect.** The number of placeholders is not a count of secrets, and it is not stable.
`FuzzIdleFlushIsInvariant` therefore compares the two results after each run of placeholders
is reduced to one. It still asserts that no needle reaches the output.

**How it was found.** The two fuzz targets in `internal/redact` failed on their own cached
corpus, and `go test ./...` did not show it, because that command runs a fuzz target only
against the few inputs in `testdata`. Both faults were in the targets, not in the filter. CI
now runs every fuzz target for a fixed number of cases on each change.

---

## D6. The cold start of `run` is 17 ms, and the keyring is not the cost

**Date:** 2026-08-15

**Measurement.** A project with two secrets on macOS on arm64, 25 runs, median. `/bin/echo x`
alone takes 1.8 ms. `secretveil run --quiet -- /bin/echo x` takes 19.1 ms through the
keychain, so the cost of the tool itself is 17.3 ms. The same project opened with
`SECRETVEIL_IDENTITY` instead of the keychain takes 20.1 ms, which is the same number inside
the error of the measurement. The binary alone, through `secretveil version`, takes 3.6 ms.

**Effect.** The gate is 50 ms and the tool uses a third of it. The keyring read is not the
part to optimise, and neither is the age file. A later change that adds a network call or a
second process to the start of `run` will show up here at once.

**A trap for the next measurement.** The first attempt reported 97 ms. The keychain entry of
that old fixture had been deleted, so every run was taking an error path. Check the exit code
of the command you are timing.

---

## D7. npm expands `${VAR}` in an `.npmrc`, so that file takes a marker and not a handle

**Date:** 2026-08-16

**Measurement.** A project `.npmrc` held `my-custom-key=${MY_TOKEN}`. With `MY_TOKEN` set to
`EXPANDED_VALUE`, `npm config get my-custom-key` returned `EXPANDED_VALUE`. With `MY_TOKEN`
unset, the same command returned the literal text `${MY_TOKEN}`. npm reads a project `.npmrc`
only when a `package.json` sits beside it.

**Reason.** An `.npmrc` cannot hold an `sv://` handle. npm reads the file from disk and sends
the value it finds to the registry, so a handle would go over the wire as if it were the
token. There is no precedence rule to lean on here, which is what makes a `.env` file work
(see D4). The variable expansion above is the one opening npm gives, and this design uses it.

**Effect.** `secretveil init` writes `${SV_NPMRC_...}` into an `.npmrc`, and `secretveil run`
puts the value in the child environment under that name. A project that forgets to use
`secretveil run` sends the literal `${SV_NPMRC_...}` to the registry, which fails with a clear
refusal and leaks nothing.

**Why the parser is narrow.** npm reads this file with its own ini parser, and that parser does
not agree with the `.env` parser on quoting or on inline comments. A line is rewritten only
when the value is a plain token: no space, no quote, no comment character. Every real registry
token has that shape. `npmrc.Line.Set` renders the candidate line and reads it back, and
refuses any write that would not read back as the same value.

**Why no shape comment.** A `.env` line gets a trailing `# sv:` comment that names the length
and the character set. An `.npmrc` line gets none, because npm parses this file itself and a
comment this tool invented could change what npm sees.

**What this does not cover.** A `.netrc` cannot be fixed at all: curl, git and ftp read it
literally and expand nothing. A `.yarnrc.yml` does expand `${VAR}`, but it is YAML and would
need a round-trip YAML parser. `doctor` reports both rather than rewriting them.

**How the design was tested.** `npm config get //registry.npmjs.org/:_authToken` refuses with
"option is protected", so the measurement above used a key npm does not protect. The end to
end check ran `secretveil run -- npm config get my-custom-key` against a marker and saw the
output filter replace the expanded token with its reference.

---

## D8. `init` rewrites every `.env` file, but `run` reads two of them

**Date:** 2026-08-16

**Measurement.** A project held `API_KEY` in `.env` and `STRIPE_DEV_KEY` in `.env.development`.
After `secretveil init`, both files held a handle. `secretveil run -- node ...` reported
`1 secret(s) from .env`, and a loader that read `.env.development` itself gave the program the
string `sv://stripe_dev_key` as the value of `STRIPE_DEV_KEY`. `secretveil doctor` on that same
project printed `Every check passed.`

**Reason for the two lists.** `IsSecretFile` accepts `.env` and every name that starts with
`.env.`, because a plaintext secret in `.env.production` is a plaintext secret and `init` has to
move it. `runtime.DefaultFiles` holds only `.env` and `.env.local`, because those two names mean
the same thing in every framework. `.env.production` does not: Next.js loads it when `NODE_ENV`
is `production`, and Vite loads it when the mode is `production`, which is a different question.
A tool that guessed would put the wrong value in a program that talks to a live system.

**Decision.** Keep both lists as they are. The default is right, and the silence about it was
the fault.

**Effect.** `doctor` gained a check. A `.env` file that holds a handle and that the default load
order does not read is named, with the whole `--env-file` command to fix it, in load order.
`init` prints that same command instead of the short one when it rewrote such a file. Neither
command guesses which file a framework wants. Both say what was not read.

**Why the advice is a whole command line.** The load order is the part a developer gets wrong. A
later file wins over an earlier one, so `.env` goes first and `.env.local` goes last. A rule to
work out is a rule to get wrong, so `runtime.LoadOrder` works it out and `runtime.RunLine`
prints it.

**Two faults found in the same area.** The reference that a rename produced did not name its
file: `slug` cut the name at the last dot, so `.env.local` and `.env.development` both became
`env`, and the second one had to take the number `2`. And `Result.Renamed` was a map from the
old name to the new one, which cannot hold one old name that became two new names, so `init`
reported one rename when it had made two. Both are fixed. `Renamed` is now a list that names
the file as well.

## D9. Provenance needs a public repository, so the flag is conditional

**Date:** 2026-08-16

**Measurement.** A dry run made every npm package from the four cross compiled binaries with
no registry involved. `node npm/build.mjs 0.1.0` passed its own platform check. `npm pack`
made five tarballs. The `darwin-arm64` tarball and the main tarball, installed together into
an empty project, gave a working `node_modules/.bin/secretveil`, and `secretveil version`
printed `0.1.0`. The registry names `secretveil` and `@secretveil/darwin-arm64` both answer
404, so both are free.

**The obstacle.** The publish step asked for `--provenance` on every package. npm refuses a
provenance statement from a private source repository and answers "Only public source
repositories are supported when publishing with provenance". GitHub stopped supporting it in
July 2023. This repository is private today, so the step would have failed after some
platform packages were already on the registry, which is worse than not asking for
provenance at all.

**Decision.** The workflow reads `github.event.repository.private` and adds `--provenance`
only when the repository is public. A private repository still publishes, and the log says
why the packages carry no provenance.

**What this does not decide.** Whether the repository becomes public. That is a choice about
the project, not about the release, and it has a second effect: the `repository` link in
every published package points at a page that answers 404 to everyone who is not a member.

**A second path.** npm trusted publishing, generally available since July 2025, lets npm
trust a named workflow through OIDC. There is then no token to make, to store or to rotate,
and provenance is written with no flag. It is configured per package and needs the package to
exist, so the first publish still uses a token.

**Update, 2026-08-18.** Two of the three conditions are met. The free `secretveil`
organisation was made on 2026-08-16, and the repository was made public the same day after a
scan of every commit found no credential and no business content. `--provenance` is therefore
active. The token is the last step and it belongs to a person, because npm asks for the
second factor before it makes one. It must be a **granular access token**, not the Automation
classic token that this record first named: npm is withdrawing classic tokens, the account
pages stop making them in August 2026, and they stop working for a publish in January 2027.
npm also limits a granular token that is made for automation to a short life, so the token is
for the first publish only. Trusted publishing takes over from the second publish.

**A trap worth writing down.** To npm a path of two parts is the name of a GitHub repository.
`npm publish npm/secretveil` reaches for `github.com/npm/secretveil` and fails with a git
permission error that names neither npm nor this project. Every command keeps the `./`.

## D10. `run` waits for the pseudo terminal to drain before it closes it

**Date:** 2026-08-16

**Measurement.** `TestAPseudoTerminalRunFiltersTheOutput` failed on `ubuntu-latest` under
`-race` with `the placeholder is missing from ""`. The child had written two lines and the
capture held nothing at all. The same test passes on macOS and passed on Linux on the runs
before it, so the fault looked like chance.

**Cause.** `runPTY` closed the pseudo terminal as soon as `cmd.Wait` returned. `cmd.Wait`
returns when the child is reaped, not when its output is read, so the copy that reads the
pseudo terminal can still have bytes to take, or can have had no turn to run at all. The
close ended that read, and the bytes went nowhere. `-race` makes a goroutine slower to be
scheduled, which is why Linux under `-race` showed it first.

**What was at stake.** This is not a test fault. A person who runs `secretveil run -- make`
could lose the last lines of the build, which are the lines that say whether it worked, and
nothing anywhere would say a line was dropped.

**Decision.** `drainPTY` waits for the copy to reach the end of the stream, then closes. A
read of the pseudo terminal reports the end as soon as the last program closes the other end,
so the normal wait is microseconds. A child that leaves a program behind holding that end
open would never report the end, so the wait is bounded by `ptyDrainGrace`, two seconds, and
the close then ends the blocked read.

**The other path was already right.** `runPipes` hands `cmd.Stdout` an `io.Writer` and not a
file, so `os/exec` makes the pipe and its own copy, and `cmd.Wait` waits for that copy. Only
the pseudo terminal path owned the copy, and only it had to own the order.

**Guard.** `TestAPseudoTerminalKeepsTheLastLine` runs a child that writes 500 lines and stops.
Every line has to arrive. Note that this test passes on macOS with the old order as well, so
Linux is where it earns its place.

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

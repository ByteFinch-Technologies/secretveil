# Threat model

Read this before you install secretveil. It tells you what the tool stops, what it does not
stop, and where the line is. A security tool that hides its limits is worse than no tool,
because you plan around a protection that is not there.

Every claim below is tested. The test set is in `test/adversarial/`, and each case names the
section it belongs to.

---

## 1. What secretveil is for

You give an AI coding agent access to your project. The agent reads files. Your `.env` file
holds an API key, a database password and a signing secret. The agent reads that file, and
now the value is in the context window of a model, in a transcript on disk, and possibly in
a log on a server you do not control.

secretveil takes the value out of the file. The file holds a handle instead:

```
API_KEY=sv://api_key    # sv: 24 chars, base64, entropy 4.5
```

The agent reads the file and learns the name, the length and the character set. It does not
learn the value. Your program still gets the real value, because `secretveil run` puts it in
the environment of the child process, and every framework gives a variable in the
environment priority over a variable in a file.

The design is deliberate: **there is no interception layer.** No proxy, no file system hook,
no plugin for each AI tool. The file on disk simply has no secret in it. That is why the
tool works with every AI tool, including one that ships next year.

---

## 2. What secretveil does NOT stop

Read this section first. It is the part that decides whether the tool fits your problem.

### 2.1 A program that gets a value can do anything with it

`secretveil run` gives the real value to the child process. It has to. A program with a
handle instead of a password cannot connect to the database.

So a program that receives the value can write it to a file, send it over the network, or
put it in a log that lands on disk. secretveil filters the **output** of the child process.
It does not control what the child process writes.

An agent that can run any build script can therefore get any secret, by writing a script
that saves the value and then reading the file. This is recorded as case 6 in the
adversarial test set, and the test asserts that the theft succeeds. It is not a fault to fix
later. It is the shape of the problem.

**What this means for you.** secretveil removes the *passive* leak, which is the common one:
the agent reads your `.env` because reading files is what it does all day. It does not stop
a *deliberate* attack by an agent that is already running arbitrary code on your machine.

### 2.2 The command rules read a name, not a program

`secretveil run` refuses to start a shell for an agent, and refuses an interpreter flag that
runs code from the command line. That is cases 1 and 2, and both are stopped.

But the rules see only the name of the program and its flags. `npm run build` is allowed,
and the script behind that name can hold `printenv`. This is case 3. The command runs, and
the only thing between the agent and the value is the output filter.

The rules exist for one narrow reason: `bash -c printenv` is the cheapest attack and the
easiest to block. Do not read them as a sandbox. They are not one.

### 2.3 The output filter has a floor

The filter removes every secret value from the output of the child process, in either
direction, across chunk boundaries, and in base64 form. It does not remove a value that is
too short to remove safely. A four character password appears in ordinary text, and a filter
that removed every four character run would destroy the output.

`run` names each value it skipped, on standard error. Use a longer value.

### 2.4 A secret already leaked stays leaked

Installing secretveil does not rotate anything. If your `.env` was in a git history, in a CI
log, or in the transcript of an agent session last week, the value is compromised now and
the tool cannot undo that. **Rotate first, install second.** A new control does not undo an
old leak.

### 2.5 The machine itself

secretveil assumes your workstation is yours. Anything running as your user can read the age
identity out of your keychain, read the memory of a running `secretveil run`, or read the
environment of the child process through `/proc` on Linux. The tool raises the cost of a
passive read of a file. It is not a defence against malware that already has your user
account.

### 2.6 What an agent still learns

By design, the agent reads the handle and the shape comment: the length, the character set
and the Shannon entropy of the value. This is deliberate, because an agent that cannot see
that `API_KEY` is 24 base64 characters will guess wrong when it writes the code that uses
it.

The shape is not the value, but it is not nothing. A 4 character numeric PIN has a shape
that describes a very small set. Do not put a low entropy secret in the store and expect the
shape comment to hide it. `run` will refuse to filter it anyway. See section 2.3.

---

## 3. What secretveil does stop

### 3.1 The passive read

This is the whole point. An AI tool that reads `.env` gets a handle. There is no
integration, no allow list of tools, and nothing to keep up to date, because there is no
value in the file to read. A tool released tomorrow is covered on the day it ships.

### 3.2 A secret in the output of a build

A value that reaches standard output or standard error of a child process is replaced with
its handle before anything downstream sees it. This covers the common accidental leak: a
stack trace that prints a connection string, a debug line that dumps a config object, a
verbose HTTP client that echoes an Authorization header.

The filter is a streaming Aho-Corasick matcher. It holds back the last `n-1` bytes so a
value split across two writes is still caught, and it matches the base64 form of each value
as well as the value itself.

### 3.3 The cheap environment dump

`bash -c printenv`, `node -e 'console.log(process.env)'`, `python3 -c 'import os; print(os.environ)'`
and their relatives are refused when the caller is an agent, and the refusal is written to
the audit log. A path in front of the name does not help: `/bin/bash` and
`C:\Windows\System32\cmd.exe` both resolve to the same program name on every platform.

### 3.4 A secret printed on request

`secretveil get` is the one command that prints a plaintext value. It needs the `--reveal`
flag **and** a human caller. An agent is refused, and both the refusal and a successful
reveal go into the audit log.

### 3.5 A file outside the project

secretveil never follows a symbolic link named `.env`. A link can point anywhere on the
machine, and following one would let `init` read a file outside the project and write a
rewritten copy inside it. Links are reported and skipped. This is case 4.

---

## 4. Who the caller is, and why it matters

Three rules get different powers:

| Caller | How it is recognised | What it may do |
|---|---|---|
| Human | Standard input and standard output are both a terminal | Everything |
| CI | A pipeline marker such as `GITHUB_ACTIONS` is set | Everything. The output filter still runs |
| Agent | A marker such as `CLAUDECODE` is set, **or nothing matched** | No shell, no inline code, no reveal |

The last row is the important one. **An unknown caller is treated as an agent.** A command
with no terminal and no marker could be a script a developer wrote, or a tool nobody has
heard of yet. The safe reading of an unknown caller is the one with the least power.

Set `SECRETVEIL_CALLER=human` to override this when it is wrong. The override is trusted,
because anything that can set an environment variable for the process can also just run the
program itself.

The marker table goes out of date. It is reviewed every quarter, and the review date is in
the source of `internal/detect`.

---

## 5. The store

Secrets live in one file, `.secretveil/secrets.age`, in the age format. The key that opens
it is an age identity, 74 characters, held in the operating system keyring.

The keyring never holds a secret value. On macOS the keychain silently truncates a value
over 128 bytes when it is written through the standard input path, which loses data with no
warning, and the command line path puts the plaintext in the process list where every user
on the machine can read it. Both are unusable for a secret of unknown length. Holding one
short identity avoids the whole problem, and it is what makes a multi-line value such as a
PEM private key work at all. The measurement is recorded as D1 in `docs/decisions.md`.

The encrypted file is safe to lose but it does not belong on a remote, so `init` adds
`.secretveil/` to `.gitignore`. `secretveil doctor` checks that this is still true.

On a machine with no keyring, set `SECRETVEIL_PASSPHRASE`. The file is then opened with
scrypt, which is slow on purpose.

---

## 6. The audit log

`.secretveil/audit.log` records every run, refusal, reveal, migration and store write. It
stays on the machine. Nothing is sent anywhere.

The log never holds a secret value. It holds the reference name, which is a label. Command
lines are redacted before they are written, because a developer types
`curl -H "Authorization: Bearer ..."` and that argument would otherwise land in the file.
The redaction is a guess and it is deliberately wide, so it sometimes hides an ordinary word
as well. A log entry is worth less than a leak.

---

## 7. Reporting a problem

See `SECURITY.md`.

If you find a way to get a plaintext value out of a project that uses secretveil, and it is
not one of the limits in section 2, that is a bug and we want to hear about it. If it is one
of the limits in section 2, it is already written down, and a test asserts it.

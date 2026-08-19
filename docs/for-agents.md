# Instructions for an AI agent

This page is for an AI coding agent that installs or operates secretveil. A person can read
it too, but the wording is for the agent. Follow it in order.

## The five rules

1. **Do not open a `.env` file to see what is in it.** Run `secretveil plan`, which prints
   the key, the class and the shape of every variable and never prints a value. A value you
   read is a value in your context, and secretveil cannot take it back.
2. **You are an agent caller.** secretveil recognises you from a marker such as `CLAUDECODE`
   in the environment. A caller it cannot recognise is also treated as an agent. You have
   less power than the person you work for, by design.
3. **You cannot undo `init`.** Only `restore` puts the plaintext back, and `restore` needs a
   human caller. Get the person to agree before you run `init`.
4. **Never run `secretveil set`.** It takes a plaintext value, so the value would pass
   through you. The person runs it, at their own terminal, with a hidden prompt.
5. **Report what you did, and name what you cannot protect.** `doctor` finds a credential in
   a file that secretveil does not rewrite. Give that list to the person. Do not call the
   project safe.

## Install it

```sh
npx secretveil doctor              # runs without an install, writes nothing
npm install --save-dev secretveil  # or install it into the project
```

`doctor` writes nothing and changes nothing, so it is always safe as a first command. It
exits 1 when it finds something that puts a secret at risk, and 0 otherwise.

Windows has no binary yet. Use the Windows Subsystem for Linux.

## Set it up

**Step 1. Find out whether it is already set up.**

```sh
ls .secretveil 2>/dev/null && secretveil list
```

A `.secretveil/` directory means the project already uses secretveil. Do not run `init`
again for a project that has it. Go to "Work in a project that already uses it".

**Step 2. Read the plan.**

```sh
secretveil plan --json
```

Use `--json` when you parse the result. Use `secretveil plan` with no flag when you show it
to a person. Neither prints a value.

**Step 3. Tell the person to rotate first.**

Say this before you write anything:

> secretveil hides a value from the moment `init` runs. It cannot undo a leak. If this `.env`
> already reached a git history, a CI log or an AI transcript, rotate those values at the
> provider first, then install.

If you read the `.env` file earlier in this session, say so plainly. Those values are in the
transcript now, and they need rotation.

**Step 4. Move the secrets.**

```sh
secretveil init -y
```

`init` needs `-y` when no terminal is attached, and yours is not attached. Without the flag
the command stops and writes nothing.

`init` puts each secret in an encrypted store, puts a handle such as `sv://api_key` in the
file, and adds `.secretveil/` to `.gitignore`.

**Step 5. Put `run` in front of every command that needs a value.**

Edit `package.json`, so that nobody has to remember it:

```json
{
  "scripts": {
    "dev": "secretveil run -- next dev",
    "test": "secretveil run -- vitest"
  }
}
```

Do not change the application code. dotenv, Next.js and Vite all give a variable in the
environment priority over the same variable in a file, so each of them keeps working.

**Step 6. Check the result and report it.**

```sh
secretveil doctor
```

Report three things to the person: the count of variables in each class, any credential file
that secretveil cannot rewrite, and the reminder to rotate.

## Work in a project that already uses it

- Put `secretveil run --` in front of any command that needs a real value. Everything else
  runs as it always did.
- `API_KEY=sv://api_key` is correct. It is not a bug and it is not a placeholder to fill in.
  Never replace a handle with a value.
- Never write a real credential into a file, a test fixture or a commit.
- A new secret is the person's job: they run `secretveil set <ref>`, then you add
  `KEY=sv://<ref>` to the file.
- `secretveil list` prints every reference in the store and no values. Use it to check that a
  handle has a value behind it.

## When a command is refused

| What you see | Why | What to do |
|---|---|---|
| `restore` is refused | It needs a human caller. It would undo the whole tool in one command. | Ask the person to run it. |
| `get --reveal` is refused | It prints a plaintext value. It needs `--reveal` and a human caller. | Use `secretveil run` instead, which gives the value to the program and keeps it out of the output. |
| `run -- bash -c ...` is refused | A shell runs anything, so allowing one allows everything. | Run the program directly: `secretveil run -- npm run build`. |
| `run -- node -e ...` is refused | An inline code flag turns an interpreter into a shell. | Put the code in a file and run the file. |
| `init` stops and writes nothing | No terminal is attached and `-y` was not given. | Run `secretveil init -y`, after the person agrees. |

Each refusal goes into the local audit log. The log never holds a value.

To change what an agent may run, a person edits `.secretveil/policy.toml`. Setting
`enforce = false` there turns the command rules off and keeps the output filter.

## What this does not protect against

You get the real values when you run `secretveil run`, because a program with a handle
instead of a password cannot connect to anything. You could write those values to a file.
secretveil filters what a program prints; it does not control what a program writes to disk.

So this is not a sandbox around you. It removes the passive read: the `.env` file you would
otherwise open because reading files is what you do all day. Read
[`threat-model.md`](threat-model.md) for the rest.

## Give this to an agent

Paste this to start:

> Install secretveil in this project. Read
> https://github.com/ByteFinch-Technologies/secretveil/blob/main/docs/for-agents.md and follow
> it. Do not open the `.env` file. Show me the plan before you change anything.

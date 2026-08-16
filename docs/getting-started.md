# Getting started

This page takes about five minutes. At the end, your `.env` file holds no secret, and your
application still runs.

## Before you start

**Rotate first, install second.** If your `.env` file has already gone into a git history, a
CI log, or the transcript of an AI tool, those values are compromised now. secretveil hides a
value from this point forward. It cannot undo a leak that already happened. Rotate the value
at the provider, put the new value in the file, and then install.

## Step 1. Look, and change nothing

```sh
cd your-project
npx secretveil plan
```

`plan` finds every `.env` file, classifies each variable, and prints the result. It writes
nothing.

```
.env
  KEY           CLASS   RULE              SHAPE
  API_KEY       veiled  value-openai-key  24 chars, base64, entropy 4.5
  NODE_ENV      open    name-open         11 chars, lower, entropy 2.4
  DATABASE_URL  partial url-password      52 chars, mixed, entropy 4.7

1 file, 3 variables: 1 open, 1 partial, 1 veiled.
```

Each variable falls into one of three classes:

- **open**: not a secret. `NODE_ENV=development` stays exactly as it is.
- **partial**: only one part of the value is a secret. In a database URL, the password is
  replaced and the host, the port and the database name stay readable.
- **veiled**: the whole value is a secret, and the whole value is replaced.

The output never prints a value. It prints the key, the class, the rule that fired, and the
shape of the value.

Read the table. If a variable is in the wrong class, say so in an issue: the classifier is
meant to be corrected.

## Step 2. Move the secrets

```sh
npx secretveil init
```

`init` asks before it writes. It then puts each secret into an encrypted store, and puts a
handle in the file:

```
# before
API_KEY=sk-live-Q9xR2mVn7pLwT4aZ

# after
API_KEY=sv://api_key    # sv: 24 chars, base64, entropy 4.5
```

`init` also adds `.secretveil/` to `.gitignore`, and writes a documented policy file at
`.secretveil/policy.toml`.

The store is one encrypted file at `.secretveil/secrets.age`. The key that opens it lives in
the keychain of your operating system, not in the project.

To undo all of this, run `secretveil restore`. It gives back the original file, byte for
byte, with an empty diff.

## Step 3. Run your application

Put `secretveil run --` in front of the command that needs the values:

```sh
npx secretveil run -- npm run dev
```

Nothing in your application changes. You keep `dotenv`, or Vite, or Next.js, exactly as it
is. `run` puts the real values in the environment of the child process, and every one of
those loaders gives a variable in the environment priority over the same variable in a file.

`run` also reads every byte the program prints and removes every secret from it, so a value
that reaches a stack trace or a debug log never reaches the screen.

Add it to your scripts so that nobody has to remember it:

```json
{
  "scripts": {
    "dev": "secretveil run -- next dev",
    "test": "secretveil run -- vitest"
  }
}
```

## Step 4. Ask what is still wrong

```sh
npx secretveil doctor
```

`doctor` names anything that would surprise you later: a handle with no value behind it, a
plaintext secret still in a file, a store that this machine cannot open, a credential in a
file that secretveil does not rewrite, and a `.env` file that `run` does not read on its own.

It writes nothing. Run it whenever you want.

## Step 5. Tell your team

Your teammates get the `.env` file from git, with the handles in it. They do not get the
store, because `.secretveil/` is in `.gitignore`. Each of them needs the values once.

Two ways to hand them over:

- **Each developer sets each value.** `secretveil set api_key` reads the value from a hidden
  prompt. It never takes a value from the command line, because every user on the machine can
  read the arguments of a running program.
- **Share the store.** Send `.secretveil/secrets.age` and the key by a channel you trust.
  The file is encrypted, and the key is separate from it.

`secretveil doctor` on their machine tells them at once whether every handle has a value.

## More than one `.env` file

`init` moves the secrets out of every `.env` file, so `.env.development` gets a handle too.
`run` reads two files on its own, `.env` and `.env.local`, because those two names mean the
same thing in every framework. Name any other file yourself:

```sh
secretveil run --env-file .env --env-file .env.development -- npm run dev
```

You do not have to work this out. `init` prints the whole command, and `doctor` warns when a
file holds a handle that `run` does not read. The reasoning is D8 in
[`decisions.md`](decisions.md).

## What your AI agent sees now

Ask the agent to read the `.env` file. It reads this:

```
API_KEY=sv://api_key    # sv: 24 chars, base64, entropy 4.5
```

The agent learns the name of the variable and the shape of the value, which is what it needs
to write correct code. It does not learn the secret.

There is nothing to configure in the agent, because there is no integration. The file on disk
has no secret in it, so every AI tool is covered, including one released after this was
written.

Read [`threat-model.md`](threat-model.md) for what this stops and what it does not.

## Next

- [`commands.md`](commands.md) — every command, every flag.
- [`ci.md`](ci.md) — the same project on a build server.
- [`faq.md`](faq.md) — the questions people ask on day two.

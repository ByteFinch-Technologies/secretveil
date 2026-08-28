# Questions people ask

## Does it work with my AI tool?

Yes, and there is nothing to set up. There is no plugin, no proxy and no integration, because
the file on disk holds no secret. Anything that reads the file reads a handle. A tool released
after this was written is covered as well.

To have an agent install it for you, give it [`for-agents.md`](for-agents.md).

## Can the agent not just run `secretveil get`?

No. `get --reveal` and `restore` need a human caller. secretveil looks at its environment for
the marker of an AI tool, and refuses. The refusal goes into the audit log.

An unknown caller is read as an agent, so a tool nobody has heard of yet is refused too.

## Then how does the agent break this?

By running your build. `secretveil run` gives the real value to the child process, because a
program with a handle instead of a password cannot reach the database. That program can write
the value to a file, and secretveil does not control what a child process writes to disk. The
adversarial test set asserts that this theft **succeeds**, so it cannot be quietly lost in a
later change.

What secretveil removes is the passive read: the agent that opens `.env` because reading
files is what it does all day. That is the common leak, and it is not an attack. Read
[`threat-model.md`](threat-model.md) for the full picture.

## Do I have to change my application?

No. Keep `dotenv`, Vite, Next.js or whatever you use. `secretveil run` puts the real values in
the environment of the child process, and every one of those loaders gives a variable in the
environment priority over the same variable in a file. Your framework loads the value exactly
the way it always did.

The measurement is D4 in [`decisions.md`](decisions.md).

## What if I forget `secretveil run`?

Your program gets the text `sv://api_key` as the value, and fails to authenticate. It fails
loudly, at the first call, with a value that is easy to search for. It does not run with a
missing key and it does not start in a wrong state.

Put `secretveil run --` in the `scripts` block of `package.json` so nobody has to remember it.

## My program under bun still sees `sv://...`

bun loads more `.env` names than `run` does. bun reads `.env`, then `.env.production` or
`.env.development` or `.env.test` by `NODE_ENV`, then `.env.local`, then the `.local` name that
matches `NODE_ENV`. `secretveil run` reads `.env` and `.env.local`.

So a handle in `.env.development` is loaded by bun and reaches your program as the text
`sv://stripe_dev_key`. Nothing leaked. The program got the handle instead of the value.

`run` prints a warning and the line to copy when it finds this:

```sh
secretveil run --env-file .env --env-file .env.development -- bun run dev
```

Name the files in load order. The last file wins, the same way bun and every other loader
behave. A variable that `run` puts in the environment beats every `.env` file that bun reads, so
the value your program gets is the real one.

`run` reads only two names by default on purpose. A wider default would change the behaviour of
every project, and only you know which of the eight names your program uses.

## What happens to the value in my git history?

Nothing. secretveil hides a value from the moment you run `init`. It cannot reach into a
commit you already pushed, a CI log, or the transcript of an AI session.

**Rotate first, install second.** A value that already leaked is compromised now, and a new
control does not undo a leak.

## How do I add a new secret?

Put the plaintext value in the `.env` file and run `init` again. It moves only what is new.

Or write it straight into the store and add the handle by hand:

```sh
secretveil set api_key
```

Then put `API_KEY=sv://api_key` in the file.

## How does a teammate get the values?

They get the `.env` file from git, with the handles. They do not get the store, because
`.secretveil/` is in `.gitignore`. Then either:

- each of them runs `secretveil set <ref>` for each value, or
- you send them `.secretveil/secrets.age` and the key, by a channel you trust.

`secretveil doctor` on their machine says at once whether every handle has a value.

## Is `.secretveil/secrets.age` safe to commit?

The file is encrypted with [age](https://age-encryption.org/), so it is not plaintext. Even
so, `init` puts it in `.gitignore`. A committed store is one file that every future holder of
the repository can attack offline. Keep it out of git.

## What if I lose the key?

The values are gone, the same as any encrypted store. The `.env` file still tells you which
secrets existed, by name and by shape, so you know exactly what to rotate at each provider.

## Can I stop using it?

Yes, and the diff is empty:

```sh
secretveil restore
```

It gives back the original file, byte for byte. That is a release gate, tested on every
fixture project.

## Why is there a comment after each handle?

```
API_KEY=sv://api_key    # sv: 24 chars, base64, entropy 4.5
```

The shape helps the agent write correct code against the variable: a 24 character base64 key
is not a 36 character UUID and not a URL. Without it, the agent guesses, and you review wrong
code.

The shape is information, and we say so plainly. Do not store a low entropy secret and expect
the comment to hide it. There is no shape comment in an `.npmrc`, because npm parses that file
with its own reader.

## My secret still appeared in the log

Two known reasons:

1. **The value is too short.** A four character password appears in ordinary text, and
   removing every four character run would destroy the output. `run` names each value it
   skipped. Use a longer value.
2. **The program wrote it to a file, not to the output.** The filter reads what the program
   prints. It does not read what the program writes to disk.

If neither fits, that is a bug worth reporting. See [`../SECURITY.md`](../SECURITY.md).

## Why not just use my cloud secret manager?

Use it. secretveil is not a replacement for a secret manager, and it does not want your
production secrets. It covers the machine where a developer works with an AI agent, which is
the place where a `.env` file sits in the clear and a program reads every file in the
project.

In CI, secretveil reads the values from the environment, so your platform stays the source of
truth. See [`ci.md`](ci.md).

## Does it work on Windows?

Not yet. It is planned for v0.3. The Windows Subsystem for Linux works today.

The npm install itself does not fail on Windows, because the platform packages are
`optionalDependencies`. The error comes only when a Windows developer runs the command, so
`npm install` in a mixed team keeps working for everybody else.

## Does it send anything anywhere?

No. There is no telemetry, no update check, and the audit log stays on the machine.

A test enforces it. The `nonetwork` suite reads the build graph of the released binary and
fails the build if a package that can move bytes off the machine is in it, such as `net/http`
or `crypto/tls`. A package that is not in the graph cannot be reached at run time, whatever
the code says.

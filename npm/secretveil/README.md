# secretveil

Let an AI coding agent work in your repository without letting it read your secrets.

Your `.env` file holds a handle instead of a value. The agent reads the file and learns the
name and the shape. It does not learn the secret. Your program still works, because
`secretveil run` puts the real value in the environment of the child process.

```
# before
API_KEY=sk-live-Q9xR2mVn7pLwT4aZ

# after
API_KEY=sv://api_key    # sv: 24 chars, base64, entropy 4.5
```

There is no plugin and no proxy. There is nothing to integrate with, because the file on
disk has no secret in it.

## Read this first: what it does NOT do

1. **A program that gets a value can leak it.** `secretveil run` gives the real value to the
   child process, because a program with a handle instead of a password cannot connect to
   the database. An agent that can run any build script can get any secret.
2. **The command rules read a name, not a program.** An agent may not run `bash -c printenv`.
   It may run `npm run build`, and that script can hold `printenv`. The output filter is the
   backstop, not a sandbox.
3. **Installing this does not rotate anything.** If your `.env` already went into a git
   history or an agent transcript, those values are compromised now. Rotate first, install
   second.

The full reasoning is in
[the threat model](https://github.com/ByteFinch-Technologies/secretveil/blob/main/docs/threat-model.md).

## Try it

```sh
npx secretveil plan
```

## Install it

```sh
npm install --save-dev secretveil
```

Then:

```sh
npx secretveil init
npx secretveil run -- npm run dev
```

## About this package

This package holds a small Node shim. The binary is in one of four packages,
`@secretveil/darwin-arm64`, `@secretveil/darwin-x64`, `@secretveil/linux-x64` and
`@secretveil/linux-arm64`, and npm installs only the one that matches your machine.

**The shim costs about 20 ms of Node start time on every call.** `secretveil run` wraps every
command you type, so for daily use install the binary itself and skip the shim:

```sh
go install github.com/ByteFinch-Technologies/secretveil/cmd/secretveil@latest
```

or take a signed archive from
[the releases page](https://github.com/ByteFinch-Technologies/secretveil/releases).

Windows is planned for v0.3. On Windows this package installs and then tells you to build
from source.

If you keep the binary somewhere else, set `SECRETVEIL_BINARY` to its path and the shim will
use it.

## Documentation

Everything is in the
[repository](https://github.com/ByteFinch-Technologies/secretveil): the command list, how a
value is classified, where the secrets live, and how the caller is recognised.

Apache 2.0.

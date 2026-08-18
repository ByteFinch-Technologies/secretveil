# secretveil documentation

secretveil keeps the plaintext value off disk. Your `.env` file holds a handle for each
secret, so every AI tool reads it safely with no integration, and your program still gets the
real value through `secretveil run`.

```sh
npx secretveil plan   # look, change nothing
npx secretveil init   # move the secrets, put handles in the files
npx secretveil run -- npm run dev
```

## Start here

| Page | Read it when |
|---|---|
| [How it works](how-it-works.html) | You want the picture before the prose. Open it in a browser. |
| [Getting started](getting-started.md) | You want the whole thing working in five minutes. |
| [Install](install.md) | You need npm, Go, a signed archive, or an install that went wrong. |
| [Commands](commands.md) | You want every command and every flag. |
| [Questions](faq.md) | Something surprised you on day two. |

## Going further

| Page | What is in it |
|---|---|
| [CI](ci.md) | The same project on a build server, with no keychain and no human. |
| [Threat model](threat-model.md) | What is stopped, what is not, and why. Read it before you rely on this. |
| [Decisions](decisions.md) | Each decision that changed the plan, with the measurement that caused it. |
| [Security policy](../SECURITY.md) | How to report a problem. |

## Two things to know before you install

**Rotate first, install second.** secretveil hides a value from the moment you run `init`. A
value that already reached a git history, a CI log or an AI transcript is compromised now,
and a new control does not undo a leak.

**An agent that can run your build can get any secret.** `secretveil run` gives the real value
to the child process, because a program with a handle instead of a password cannot connect to
anything. What secretveil removes is the passive read: the agent that opens `.env` because
reading files is what it does all day. The [threat model](threat-model.md) is honest about
the rest, and the adversarial test set asserts the theft that still works.

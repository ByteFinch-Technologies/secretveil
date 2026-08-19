# secretveil documentation

secretveil keeps the plaintext value off disk. Your `.env` file holds a handle for each
secret, so every AI tool reads it safely with no integration, and your program still gets the
real value through `secretveil run`.

```sh
npx secretveil plan   # look, change nothing
npx secretveil init   # move the secrets, put handles in the files
npx secretveil run -- npm run dev
```

The quickstart, and the limits you should read before you rely on this, are in the
[main README](../README.md).

| Page | Read it when |
|---|---|
| [How it works](how-it-works.html) | You want the picture before the prose. Open it in a browser. |
| [For agents](for-agents.md) | An AI agent installs or operates this. |
| [Install](install.md) | You need npm, Go, a signed archive, or an install that went wrong. |
| [Commands](commands.md) | You want every command and every flag. |
| [CI](ci.md) | The build server has no keychain and no human. |
| [Questions](faq.md) | Something surprised you on day two. |
| [Threat model](threat-model.md) | You are deciding whether to rely on this. |
| [Decisions](decisions.md) | You want the measurement behind a decision. |
| [Security policy](../SECURITY.md) | You have a problem to report. |

**Rotate first, install second.** secretveil hides a value from the moment you run `init`. A
value that already reached a git history, a CI log or an AI transcript is compromised now,
and a new control does not undo a leak.

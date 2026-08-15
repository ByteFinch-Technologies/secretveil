# Security

## Report a problem

Email **security@bytefinch.dev**. Do not open a public issue for a vulnerability.

Tell us:

- what you did, in enough detail for us to do it again
- what you got, and what you expected instead
- the version, from `secretveil version`, and the operating system

You get a reply within 3 working days. If the report is valid, we agree a date to publish
with you. We credit you unless you ask us not to.

## What counts as a vulnerability

A way to get a plaintext value out of a project that uses secretveil, which is **not** one
of the documented limits below.

Examples of a real report:

- A value that reaches the terminal through `secretveil run` without going through the
  output filter.
- A command that an agent caller may run, which prints an environment variable in the clear.
- A way to read the store, or the age identity, without the keyring.
- `secretveil restore` giving back different bytes from the original file.
- A secret value written into `.secretveil/audit.log`.
- `init` following a symbolic link, or writing outside the project.

## What is a documented limit, not a vulnerability

These are written down in [`docs/threat-model.md`](docs/threat-model.md) section 2, and the
adversarial test set asserts each one. A report that repeats one of them is already known.

1. **A child process can write a secret to a file.** `secretveil run` gives the real value
   to the program, because otherwise the program cannot work. What the program then does
   with the value is outside the tool. This is case 6 in `test/adversarial/`, and the test
   asserts the theft succeeds.

2. **A script the policy permits can dump the environment.** The command rules read the name
   of a program and its flags, not what the program does. `npm run build` is allowed and the
   script behind it can hold `printenv`. The output filter is the backstop, and case 3
   asserts the filter holds.

3. **A very short value is not filtered.** A value too short to remove without destroying
   ordinary text is left visible, and `run` says so on standard error.

4. **The shape of a value is disclosed on purpose.** The length, the character set and the
   entropy are in the file so an agent can write correct code. This is the design.

5. **Anything running as your user can read the store.** secretveil is not a defence against
   malware that already has your account. It raises the cost of a passive read of a file.

6. **A value that leaked before you installed the tool is still leaked.** Rotate it.

If you believe one of these limits is drawn in the wrong place, that is a design discussion
and a public issue is the right place for it.

## Supported versions

v0.1 is the current release. Only the latest release gets a fix.

## What we do

- No secret value is ever written to the audit log, to a plan, or to any diagnostic output.
- No corpus, fixture or test in this repository holds a real credential. Every value is
  invented.
- A release is built by CI from a tagged commit, and the checksums are signed.

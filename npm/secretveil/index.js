// Find the secretveil binary for this machine.
//
// The binary is not in this package. It is in one of four platform packages,
// and npm installs only the one that matches the machine. The "os" and "cpu"
// fields in each platform package tell npm which one that is, and
// optionalDependencies lets the install finish on a machine we do not support
// yet.
//
// This file also works for a tool that wants the path and not a child process:
//
//	const { binaryPath } = require("secretveil");

"use strict";

const packages = {
  "darwin arm64": "@secretveil/darwin-arm64",
  "darwin x64": "@secretveil/darwin-x64",
  "linux x64": "@secretveil/linux-x64",
  "linux arm64": "@secretveil/linux-arm64",
};

const notSupportedYet = {
  win32: "Windows support is planned for v0.3.",
};

/**
 * binaryPath returns the full path of the secretveil binary.
 *
 * It throws an Error with an instruction in it when the binary is missing. A
 * developer who reads the message must know what to do next.
 *
 * @returns {string}
 */
function binaryPath() {
  const override = process.env.SECRETVEIL_BINARY;
  if (override) {
    return override;
  }

  const key = `${process.platform} ${process.arch}`;
  const name = packages[key];
  if (!name) {
    const extra = notSupportedYet[process.platform];
    throw new Error(
      `secretveil has no binary for ${key}.\n` +
        (extra ? `${extra}\n` : "") +
        "Build it from source with:\n" +
        "  go install github.com/ByteFinch-Technologies/secretveil/cmd/secretveil@latest\n" +
        "Then set SECRETVEIL_BINARY to the path of the result."
    );
  }

  try {
    return require.resolve(`${name}/bin/secretveil`);
  } catch {
    throw new Error(
      `secretveil is installed but ${name} is not.\n` +
        "This happens when the install ran with --no-optional, or when a lock file\n" +
        "was made on a different platform.\n" +
        "Try:\n" +
        `  npm install ${name}\n` +
        "or reinstall secretveil without --no-optional."
    );
  }
}

module.exports = { binaryPath, packages };

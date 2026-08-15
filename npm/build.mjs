// Make the npm packages from the binaries that goreleaser built.
//
// There are five packages. One is "secretveil", which holds only a shim and is
// checked into the repository. The other four hold one binary each and are
// made here, so that the name, the platform and the version have one source of
// truth and cannot drift apart.
//
// Run it after a release build:
//
//	goreleaser release --snapshot --clean --skip=sign,publish
//	node npm/build.mjs 0.1.0
//
// The result is npm/platforms/, which is not checked in.
//
// Then publish, the platform packages first, because the main package depends
// on them:
//
//	for d in npm/platforms/*; do npm publish "$d" --access public --provenance; done
//	npm publish npm/secretveil --access public --provenance

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");
const out = path.join(here, "platforms");

// The four platforms of v0.1. The key is the goos and goarch that goreleaser
// reports. The npm name uses the words that Node uses, which are not the same
// words: Node says x64 where Go says amd64.
const targets = [
  { goos: "darwin", goarch: "arm64", os: "darwin", cpu: "arm64" },
  { goos: "darwin", goarch: "amd64", os: "darwin", cpu: "x64" },
  { goos: "linux", goarch: "amd64", os: "linux", cpu: "x64" },
  { goos: "linux", goarch: "arm64", os: "linux", cpu: "arm64" },
];

function fail(message) {
  process.stderr.write(`npm/build.mjs: ${message}\n`);
  process.exit(1);
}

const version = process.argv[2];
if (!version) {
  fail("give the version as the first argument, for example: node npm/build.mjs 0.1.0");
}
if (!/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(version)) {
  fail(`"${version}" is not a version. Use 0.1.0, and no leading v.`);
}

// artifacts.json is read instead of the directory names, because goreleaser
// puts the processor variant in a directory name and that name changes when
// the Go release changes.
const artifactsFile = path.join(root, "dist", "artifacts.json");
if (!fs.existsSync(artifactsFile)) {
  fail(`${artifactsFile} is missing. Run goreleaser first.`);
}
const artifacts = JSON.parse(fs.readFileSync(artifactsFile, "utf8"));

function binaryFor(target) {
  const matches = artifacts.filter(
    (a) => a.type === "Binary" && a.goos === target.goos && a.goarch === target.goarch
  );
  if (matches.length !== 1) {
    fail(
      `expected one binary for ${target.goos}/${target.goarch} and found ${matches.length}. ` +
        "Check the builds section of .goreleaser.yaml."
    );
  }
  return path.resolve(root, matches[0].path);
}

const license = fs.readFileSync(path.join(root, "LICENSE"));

fs.rmSync(out, { recursive: true, force: true });

for (const target of targets) {
  const name = `@secretveil/${target.os}-${target.cpu}`;
  const dir = path.join(out, `${target.os}-${target.cpu}`);
  fs.mkdirSync(path.join(dir, "bin"), { recursive: true });

  const source = binaryFor(target);
  const destination = path.join(dir, "bin", "secretveil");
  fs.copyFileSync(source, destination);
  // npm keeps the file mode in the tarball, and the shim runs this file
  // directly, so the execute bit has to be set here.
  fs.chmodSync(destination, 0o755);

  const manifest = {
    name,
    version,
    description: `The secretveil binary for ${target.os} ${target.cpu}.`,
    homepage: "https://github.com/ByteFinch-Technologies/secretveil#readme",
    repository: {
      type: "git",
      url: "git+https://github.com/ByteFinch-Technologies/secretveil.git",
    },
    license: "Apache-2.0",
    author: "ByteFinch Technologies",
    // npm reads these two and skips the package on any other machine.
    os: [target.os],
    cpu: [target.cpu],
    files: ["bin/secretveil", "LICENSE"],
    // Yarn keeps a package in a zip file by default, and a binary in a zip
    // file cannot be run. This asks Yarn to write it to disk.
    preferUnplugged: true,
  };

  fs.writeFileSync(path.join(dir, "package.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  fs.writeFileSync(path.join(dir, "LICENSE"), license);

  const size = fs.statSync(destination).size;
  process.stdout.write(`${name}  ${(size / 1024 / 1024).toFixed(1)} MB  from ${matchPath(source)}\n`);
}

// The main package names each platform package as an optional dependency, and
// every version has to be the one being released. A wrong version here gives a
// developer the binary of an older release with no warning at all.
const mainFile = path.join(here, "secretveil", "package.json");
const main = JSON.parse(fs.readFileSync(mainFile, "utf8"));
main.version = version;
main.optionalDependencies = {};
for (const target of targets.slice().sort((a, b) => (a.os + a.cpu < b.os + b.cpu ? -1 : 1))) {
  main.optionalDependencies[`@secretveil/${target.os}-${target.cpu}`] = version;
}
fs.writeFileSync(mainFile, `${JSON.stringify(main, null, 2)}\n`);
fs.writeFileSync(path.join(here, "secretveil", "LICENSE"), license);
process.stdout.write(`secretveil ${version}  with ${targets.length} optional dependencies\n`);

// A last check. The binary that a Linux user gets must be a Linux binary. This
// has gone wrong in other projects and it is silent when it does.
for (const target of targets) {
  const file = path.join(out, `${target.os}-${target.cpu}`, "bin", "secretveil");
  const said = execFileSync("file", ["-b", file], { encoding: "utf8" }).toLowerCase();
  const wantOS = target.os === "darwin" ? "mach-o" : "elf";
  // "file" spells the same processor two ways: x86_64 for a Mach-O binary and
  // x86-64 for an ELF one. Accept both.
  const wantCPU = target.cpu === "arm64" ? ["arm64", "aarch64"] : ["x86_64", "x86-64"];
  if (!said.includes(wantOS) || !wantCPU.some((w) => said.includes(w))) {
    fail(`${target.os}-${target.cpu} holds the wrong binary. "file" says: ${said.trim()}`);
  }
}
process.stdout.write("every package holds the binary for its own platform\n");

function matchPath(p) {
  return path.relative(root, p);
}

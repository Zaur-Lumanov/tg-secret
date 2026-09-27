# Development

## Repository layout

A Yarn 1 workspaces monorepo:

```
packages/
  core/        tg-secret-core — the library; public API in src/index.ts
  cli/         tg-secret      — the console client (bin: tg-secret, tg-secret-cli)
  cli-alias/   tg-secret-cli  — the same client under a second name
docs/          documents shared by the packages
```

The core never talks to the terminal and never reads `process.argv`: everything interactive goes through the `Prompts` interface, and everything configurable is an option of `TgSecret.open()`. The CLI imports the core only through its public API (`import … from "tg-secret-core"`).

## Requirements

- Node.js 24.7 or newer
- Yarn 1 (`npm install -g yarn`)

## Commands

Run from the repository root:

```sh
yarn install
yarn start +79991234567   # the same as `tg-secret`, straight from the TypeScript sources
yarn auth  +79991234567   # the same as `tg-secret auth`: sign in only
yarn test                 # unit tests of every package
yarn typecheck
yarn build                # packages/*/dist, and the Touch ID helper on macOS
```

On macOS, Touch ID needs a native helper: `yarn build:touchid` compiles `packages/core/native/touchid.swift` into `packages/core/native/tg-secret-touchid` (a universal binary with an ad-hoc signature; needs the Xcode Command Line Tools, `xcode-select --install`). `yarn start` runs from sources but uses this binary, so build it once. A release must be built on macOS with `node scripts/build-touchid.mjs --required`, so that the published package includes it.

`yarn start` and `yarn auth` accept the client's arguments (`--debug`, `--data-dir`, `--password`) and don't change the current directory, so relative paths in `/send` work as expected.

## How the packages find each other

All packages are ESM. In development, `tg-secret-core` resolves to its TypeScript sources through a custom export condition:

```jsonc
// packages/core/package.json
"exports": {
  ".": {
    "tg-secret-source": "./src/index.ts",   // development
    "types": "./dist/index.d.ts",           // published
    "default": "./dist/index.js"
  }
}
```

TypeScript uses it through `customConditions` in `tsconfig.base.json`, and the scripts run Node with `--conditions=tg-secret-source --import tsx`. So the CLI runs and type-checks against the core's current sources with no build step. `tsconfig.build.json` of each package turns the condition off, so a build of the CLI compiles against the core's `dist` (which is why `yarn build` builds the core first).

Relative imports inside the packages end in `.js`, as ESM requires.

## Tests

`node:test` with `tsx`, in `packages/*/test`. Tests don't touch the network or the real data directory: they use temporary directories and fake clients. Unlock-method tests with hardware run against a simulated card.

## CI and releases

[CI](../.github/workflows/ci.yml) runs on every push to `main` and every pull request: type check, tests, build and a packing dry run on Windows, Linux and macOS, with Node.js 24.7 (the minimum), the latest 24 and 26. On macOS it also builds the Touch ID helper.

All three packages share one version. To release:

```sh
node scripts/version.mjs 0.2.0   # sets it in every package and in their dependencies on each other
git commit -am "chore(repo): release 0.2.0"
git tag v0.2.0
git push origin main v0.2.0
```

The [release workflow](../.github/workflows/release.yml) starts on the tag: it builds the Touch ID helper on macOS, checks that the tag matches the packages, runs the tests and publishes `tg-secret-core`, `tg-secret` and `tg-secret-cli` in that order through npm trusted publishing, with provenance. Versions that are already on npm are skipped, so a failed run can be restarted.

## Commits

[Conventional Commits](https://www.conventionalcommits.org/) with a scope naming the part of the project:

```
feat(core): …     the library
fix(cli): …       the console client (and its alias package)
chore(repo): …    the workspace itself: root configs, docs, CI
```

One commit, one scope. A change that touches both the core and the CLI becomes two commits: the core first, then the CLI that uses it.

Everything in the repository is written in English: code, comments, messages, documentation and commit messages.

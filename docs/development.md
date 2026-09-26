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

- Node.js 22.12 or newer
- Yarn 1 (`npm install -g yarn`)

## Commands

Run from the repository root:

```sh
yarn install
yarn start +79991234567   # the same as `tg-secret`, straight from the TypeScript sources
yarn auth  +79991234567   # the same as `tg-secret auth`: sign in only
yarn test                 # unit tests of every package
yarn typecheck
yarn build                # packages/*/dist
```

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

## Commits

[Conventional Commits](https://www.conventionalcommits.org/) with a scope naming the part of the project:

```
feat(core): …     the library
fix(cli): …       the console client (and its alias package)
chore(repo): …    the workspace itself: root configs, docs, CI
```

One commit, one scope. A change that touches both the core and the CLI becomes two commits: the core first, then the CLI that uses it.

Everything in the repository is written in English: code, comments, messages, documentation and commit messages.

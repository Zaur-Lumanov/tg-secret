// `import "tg-secret-cli"` lands here: this package is the command-line app, not the library.
throw new Error(
  '"tg-secret-cli" is a command-line app: run it with `tg-secret-cli` or `tg-secret` (or `npx tg-secret-cli`).\n' +
    'To use the library in your code, install "tg-secret-core":\n' +
    "  npm install tg-secret-core",
);

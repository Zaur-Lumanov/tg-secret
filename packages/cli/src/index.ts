// `import "tg-secret"` lands here: this package is the command-line app, not the library.
throw new Error(
  '"tg-secret" is a command-line app: run it with `tg-secret` (or `npx tg-secret`).\n' +
    'To use the library in your code, install "tg-secret-core":\n' +
    "  npm install tg-secret-core",
);

export {};

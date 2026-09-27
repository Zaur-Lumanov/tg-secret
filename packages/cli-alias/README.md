# tg-secret-cli

Console client for Telegram **secret chats** (end-to-end encrypted).

This package is the same app as [`tg-secret`](../cli/README.md) under a second name. Both packages install both commands, `tg-secret` and `tg-secret-cli`.

```sh
npm install -g tg-secret-cli     # or: yarn global add tg-secret-cli
tg-secret +79991234567
```

Install only one of the two packages globally: they provide the same commands, and if both are installed, uninstalling one of them removes the commands of the other too.

Documentation: [tg-secret](../cli/README.md). For the library, see [tg-secret-core](../core/README.md).

## License

MIT

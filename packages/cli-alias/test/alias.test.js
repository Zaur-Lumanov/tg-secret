import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const pkg = (path) => JSON.parse(readFileSync(new URL(path, import.meta.url), "utf8"));

test("both packages install both commands", () => {
  const alias = pkg("../package.json");
  const main = pkg("../../cli/package.json");
  assert.deepEqual(Object.keys(alias.bin).sort(), ["tg-secret", "tg-secret-cli"]);
  assert.deepEqual(Object.keys(main.bin).sort(), ["tg-secret", "tg-secret-cli"]);
  assert.equal(alias.dependencies[main.name], `^${main.version}`, "the alias follows the main package version");
});

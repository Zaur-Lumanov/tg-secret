import assert from "node:assert/strict";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { platformDataRoot, resolveDataDir, SEPARATE_DIR_NAME, SHARED_DIR_NAME } from "../src/dataDir.js";

test("data directory: shared by default, separate next to it, or an explicit path", () => {
  const shared = resolveDataDir();
  assert.equal(shared, join(platformDataRoot(), SHARED_DIR_NAME));
  assert.equal(resolveDataDir({ storage: "shared" }), shared);

  const separate = resolveDataDir({ storage: "separate" });
  assert.equal(separate, join(platformDataRoot(), SEPARATE_DIR_NAME));
  assert.equal(dirname(separate), dirname(shared), "separate lives next to the shared one");

  assert.equal(resolveDataDir({ dataDir: "some/dir" }), resolve("some/dir"));
  assert.throws(() => resolveDataDir({ dataDir: "x", storage: "separate" }), /either "dataDir" or "storage"/);
});

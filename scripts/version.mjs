// All three packages share one version. `node scripts/version.mjs 0.2.0` sets it everywhere,
// including the ranges the packages depend on each other with; `node scripts/version.mjs`
// prints the current one and fails if the packages disagree (the release workflow checks
// it against the tag this way).
import { readFileSync, writeFileSync } from "node:fs";

const PACKAGES = ["core", "cli", "cli-alias"].map((dir) => new URL(`../packages/${dir}/package.json`, import.meta.url));
const NAMES = ["tg-secret-core", "tg-secret", "tg-secret-cli"];

const read = (url) => JSON.parse(readFileSync(url, "utf8"));
const next = process.argv[2];

if (!next) {
  const versions = new Set(PACKAGES.map((url) => read(url).version));
  if (versions.size !== 1) {
    console.error(`the packages have different versions: ${[...versions].join(", ")}`);
    process.exit(1);
  }
  console.log([...versions][0]);
  process.exit(0);
}

if (!/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(next)) {
  console.error(`not a version: ${next}`);
  process.exit(1);
}

for (const url of PACKAGES) {
  const pkg = read(url);
  pkg.version = next;
  for (const name of NAMES) if (pkg.dependencies?.[name]) pkg.dependencies[name] = `^${next}`;
  writeFileSync(url, JSON.stringify(pkg, null, 2) + "\n");
}
console.log(`version ${next} set; now commit it, tag v${next} and push the tag`);

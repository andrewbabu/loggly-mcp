import { readFileSync } from "node:fs";
import { resolve } from "node:path";

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function extractToolNames(source) {
  const pattern = /registerToolWithResource\(\s*["'`](.*?)["'`]/g;
  const names = new Set();
  let match;
  while ((match = pattern.exec(source))) {
    names.add(match[1]);
  }
  return names;
}

const root = resolve(".");
const source = readFileSync(resolve(root, "src/server.js"), "utf8");
const manifest = readJson(resolve(root, "tool-manifest.json"));
const pkg = readJson(resolve(root, "package.json"));

const sourceToolNames = extractToolNames(source);
const manifestToolNames = new Set(
  (manifest.tools || []).map((tool) => tool.name).filter(Boolean)
);

if (sourceToolNames.size === 0) {
  console.error("No tools found in src/server.js.");
  process.exit(1);
}

const missingInManifest = [...sourceToolNames].filter(
  (name) => !manifestToolNames.has(name)
);
const extraInManifest = [...manifestToolNames].filter(
  (name) => !sourceToolNames.has(name)
);

if (missingInManifest.length > 0) {
  console.error("Manifest missing tools:", missingInManifest.join(", "));
}

if (extraInManifest.length > 0) {
  console.error("Manifest has unknown tools:", extraInManifest.join(", "));
}

if (manifest.version !== pkg.version) {
  console.error(
    `Manifest version (${manifest.version}) does not match package.json (${pkg.version}).`
  );
}

if (!manifest.name) {
  console.error("Manifest is missing a name.");
}

if (missingInManifest.length > 0 || extraInManifest.length > 0) {
  process.exit(1);
}

if (manifest.version !== pkg.version || !manifest.name) {
  process.exit(1);
}

console.log(
  `Tool manifest OK. ${sourceToolNames.size} tools verified for ${manifest.name} v${manifest.version}.`
);

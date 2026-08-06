import { access, readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

const root = path.resolve(process.argv[2] ?? process.cwd());
const required = [
  "dist/index.js",
  "package.json",
  "node_modules/@modelcontextprotocol/sdk/package.json",
  "node_modules/zod/package.json",
];

for (const relative of required) {
  await access(path.join(root, relative));
}

const packageJson = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));
const nodeMajor = Number.parseInt(process.versions.node.split(".")[0] ?? "0", 10);
if (nodeMajor < 20) {
  throw new Error(`Node.js 20 or newer is required; found ${process.versions.node}`);
}

process.stdout.write(
  JSON.stringify(
    {
      ok: true,
      package: packageJson.name,
      version: packageJson.version,
      node: process.versions.node,
      root,
    },
    null,
    2,
  ) + "\n",
);

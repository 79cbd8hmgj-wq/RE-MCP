import { access, readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

const root = path.resolve(process.argv[2] ?? process.cwd());
const required = [
  "dist/index.js",
  "package.json",
  "node_modules/@modelcontextprotocol/sdk/package.json",
  "node_modules/zod/package.json",
  "node_modules/@alexaltea/capstone-js/package.json",
  "node_modules/@alexaltea/capstone-js/dist/capstone.js",
  "node_modules/@alexaltea/capstone-js/dist/capstone.wasm",
];

for (const relative of required) {
  await access(path.join(root, relative));
}

const packageJson = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));
const nodeMajor = Number.parseInt(process.versions.node.split(".")[0] ?? "0", 10);
if (nodeMajor < 20) {
  throw new Error(`Node.js 20 or newer is required; found ${process.versions.node}`);
}

const adapterUrl = pathToFileURL(
  path.join(root, "dist/services/disassembly/capstone.js"),
).href;
const { createCapstoneArmBackend } = await import(adapterUrl);
const backend = await createCapstoneArmBackend();
try {
  const arm = backend.decodeOne(
    Uint8Array.from([0x1e, 0xff, 0x2f, 0xe1]),
    0x02000000,
    "arm",
  );
  const thumb = backend.decodeOne(
    Uint8Array.from([0x70, 0x47]),
    0x02000010,
    "thumb",
  );
  if (arm?.mnemonic !== "bx" || arm.size !== 4) {
    throw new Error("Packaged Capstone ARM smoke decode failed");
  }
  if (thumb?.mnemonic !== "bx" || thumb.size !== 2) {
    throw new Error("Packaged Capstone Thumb smoke decode failed");
  }
} finally {
  backend.close();
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

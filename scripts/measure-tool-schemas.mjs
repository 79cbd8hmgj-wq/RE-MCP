#!/usr/bin/env node

import { measureToolSchemas } from "./tool-schema-measurement.mjs";

const profile = process.argv[2] ?? "re-static-core";
const result = await measureToolSchemas(profile);
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);

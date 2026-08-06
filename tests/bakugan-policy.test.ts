import assert from "node:assert/strict";
import test from "node:test";

import {
  assertGeneratedAnalysisPath,
  qualityCommand,
  qualityStages,
} from "../src/tools/bakugan-policy.js";

test("full quality suite has a fixed fail-fast order", () => {
  assert.deepEqual(qualityStages("full"), ["compile", "ruff", "mypy", "tests"]);
});

test("quality commands are explicit and shell-free", () => {
  assert.deepEqual(qualityCommand("compile"), [
    "-m",
    "compileall",
    "-q",
    "src",
    "tests",
    "tools",
  ]);
  assert.deepEqual(qualityCommand("ruff"), ["-m", "ruff", "check", "."]);
  assert.deepEqual(qualityCommand("mypy"), ["-m", "mypy"]);
  assert.deepEqual(qualityCommand("tests"), ["-m", "pytest", "-q"]);
});

test("generated roster reports stay below analysis/generated", () => {
  assert.equal(
    assertGeneratedAnalysisPath(
      "/workspace/Bakugan-DS-",
      "analysis/generated/roster.json",
    ),
    "/workspace/Bakugan-DS-/analysis/generated/roster.json",
  );
  assert.throws(
    () => assertGeneratedAnalysisPath("/workspace/Bakugan-DS-", "analysis/roster.json"),
    /analysis\/generated/,
  );
  assert.throws(
    () => assertGeneratedAnalysisPath("/workspace/Bakugan-DS-", "analysis/generated"),
    /analysis\/generated/,
  );
  assert.throws(
    () =>
      assertGeneratedAnalysisPath(
        "/workspace/Bakugan-DS-",
        "analysis/generated/../../secrets.json",
      ),
    /analysis\/generated/,
  );
});

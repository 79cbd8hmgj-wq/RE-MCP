import { createHash } from "node:crypto";
import { access, readFile } from "node:fs/promises";
import path from "node:path";

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import type { ServerConfig } from "../config.js";
import { resolveInside, assertSimpleProjectName } from "../security/paths.js";
import { runProcess } from "../services/process-runner.js";
import {
  assertGeneratedAnalysisPath,
  qualityCommand,
  qualityStages,
  type BakuganQualityStage,
} from "./bakugan-policy.js";

const BAKUGAN_PROJECT = "Bakugan-DS-";
const M6E_AUTHORING = "config/gates/milestone-6e-system2-v1.json";
const M6E_METADATA = "config/gates/milestone-6e-roster-metadata.json";

function textResult(value: unknown, isError = false) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }],
    isError,
  };
}

function projectDirectory(config: ServerConfig, project: string): string {
  return resolveInside(config.workspaceRoot, assertSimpleProjectName(project));
}

async function runPython(
  config: ServerConfig,
  cwd: string,
  args: readonly string[],
  timeoutMs = config.commandTimeoutMs,
) {
  return await runProcess({
    executable: "python",
    args,
    cwd,
    timeoutMs,
    maxOutputBytes: config.maxOutputBytes,
  });
}

export function registerBakuganTools(server: McpServer, config: ServerConfig): void {
  server.tool(
    "bakugan_run_quality_suite",
    "Run an allowlisted Bakugan verification stage without accepting arbitrary commands.",
    {
      stage: z.enum(["compile", "ruff", "mypy", "tests", "full"]),
      project: z.string().default(BAKUGAN_PROJECT),
    },
    async ({ stage, project }) => {
      try {
        const cwd = projectDirectory(config, project);
        await access(path.join(cwd, "pyproject.toml"));
        const results = [];
        for (const current of qualityStages(stage as BakuganQualityStage)) {
          const result = await runPython(config, cwd, qualityCommand(current));
          results.push({ stage: current, ...result });
          if (result.exitCode !== 0 || result.timedOut) {
            return textResult({ ok: false, results }, true);
          }
        }
        return textResult({ ok: true, results });
      } catch (error) {
        return textResult({ error: error instanceof Error ? error.message : String(error) }, true);
      }
    },
  );

  server.tool(
    "bakugan_regenerate_m6e_contracts",
    "Regenerate Milestone 6E contracts using the repository-owned generator.",
    { project: z.string().default(BAKUGAN_PROJECT) },
    async ({ project }) => {
      try {
        const cwd = projectDirectory(config, project);
        const script = path.join(cwd, ".github", "scripts", "m6e_task10_contracts.py");
        await access(script);
        const result = await runPython(config, cwd, [script]);
        return textResult(result, result.exitCode !== 0 || result.timedOut);
      } catch (error) {
        return textResult({ error: error instanceof Error ? error.message : String(error) }, true);
      }
    },
  );

  server.tool(
    "bakugan_install_m6e_dry_run",
    "Run the transactional Milestone 6E installer in dry-run mode against an allowed workspace.",
    {
      project: z.string().default(BAKUGAN_PROJECT),
      workspace: z.string().min(1),
    },
    async ({ project, workspace }) => {
      try {
        const cwd = projectDirectory(config, project);
        const workspacePath = resolveInside(config.workspaceRoot, workspace);
        await access(path.join(workspacePath, "manifests", "workspace.json"));
        await access(path.join(cwd, M6E_AUTHORING));
        const result = await runPython(config, cwd, [
          "-m",
          "bakugan_ds.cli",
          "gate",
          "install-milestone-6e",
          workspacePath,
          "--authoring",
          path.join(cwd, M6E_AUTHORING),
          "--dry-run",
        ]);
        return textResult(result, result.exitCode !== 0 || result.timedOut);
      } catch (error) {
        return textResult({ error: error instanceof Error ? error.message : String(error) }, true);
      }
    },
  );

  server.tool(
    "bakugan_analyze_m6e_roster",
    "Generate the Milestone 6E roster report into the repository's allowed generated-analysis directory.",
    {
      project: z.string().default(BAKUGAN_PROJECT),
      output: z.string().default("analysis/generated/milestone-6e-roster-analysis.json"),
    },
    async ({ project, output }) => {
      try {
        const cwd = projectDirectory(config, project);
        const outputPath = assertGeneratedAnalysisPath(cwd, output);
        const result = await runPython(config, cwd, [
          "-m",
          "bakugan_ds.cli",
          "gate",
          "report-milestone-6e-roster",
          path.join(cwd, M6E_AUTHORING),
          outputPath,
          "--metadata",
          path.join(cwd, M6E_METADATA),
        ]);
        return textResult(result, result.exitCode !== 0 || result.timedOut);
      } catch (error) {
        return textResult({ error: error instanceof Error ? error.message : String(error) }, true);
      }
    },
  );

  server.tool(
    "verify_file_sha256",
    "Verify one file under the dedicated workspace against an expected SHA-256 digest.",
    {
      file: z.string().min(1),
      expectedSha256: z.string().regex(/^[a-fA-F0-9]{64}$/),
    },
    async ({ file, expectedSha256 }) => {
      try {
        const filePath = resolveInside(config.workspaceRoot, file);
        const data = await readFile(filePath);
        const actualSha256 = createHash("sha256").update(data).digest("hex");
        const normalizedExpected = expectedSha256.toLowerCase();
        const matches = actualSha256 === normalizedExpected;
        return textResult(
          { file: filePath, actualSha256, expectedSha256: normalizedExpected, matches },
          !matches,
        );
      } catch (error) {
        return textResult({ error: error instanceof Error ? error.message : String(error) }, true);
      }
    },
  );
}

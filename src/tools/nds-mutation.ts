import path from "node:path";

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import type { ServerConfig } from "../config.js";
import { resolveInside } from "../security/paths.js";
import {
  NdsError,
  type NdsServiceErrorCategory,
} from "../services/nds/errors.js";
import {
  buildNdsMutation,
  verifyPublishedNdsMutationBuild,
  type NdsMutationBuildResult,
} from "../services/nds/mutation/build.js";
import { loadNdsMutationManifest } from "../services/nds/mutation/manifest.js";
import {
  compileNdsMutationPlan,
  serializeResolvedNdsMutationPlan,
} from "../services/nds/mutation/planner.js";
import { readNdsRomMap } from "../services/nds/rom-map.js";

const mutationInputSchema = {
  rom: z.string().min(1),
  manifest: z.string().min(1),
};

type MutationToolResult = {
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
};

function sanitizeMessage(workspaceRoot: string, message: string): string {
  const resolvedRoot = path.resolve(workspaceRoot);
  return message.split(resolvedRoot).join("<workspace>");
}

function correctiveAction(category: NdsServiceErrorCategory): string {
  switch (category) {
    case "source-rom-mismatch":
      return "Use the exact source ROM revision and SHA-256 required by the mutation manifest, then retry from a freshly parsed source.";
    case "mutation-manifest-invalid":
      return "Fix the strict mutation manifest schema and keep the manifest and all referenced artifacts inside the configured workspace.";
    case "unsupported-mutation-target":
      return "Use a supported canonical ARM9, ARM7, overlay, or NitroFS selector; Milestone 1 does not expose arbitrary ROM offsets or output paths.";
    case "structural-metadata-mutation":
      return "Move the requested edit outside immutable NDS header/FAT/FNT/overlay-table structure; structural rebuilding is not supported in Milestone 1.";
    case "ambiguous-runtime-target":
      return "Select the exact overlay or use an unambiguous canonical target instead of asking RE-MCP to guess runtime ownership.";
    case "original-byte-guard-failed":
    case "original-component-guard-failed":
      return "Re-check the exact source ROM revision and refresh the manifest guard from verified original bytes or component SHA-256.";
    case "replacement-artifact-missing":
      return "Provide the declared regular non-symlink replacement artifact beneath the configured workspace.";
    case "replacement-artifact-hash-mismatch":
      return "Re-hash the replacement artifact and update the manifest only after confirming the intended artifact bytes.";
    case "replacement-size-mismatch":
      return "Provide an exact same-size stored replacement; variable-size relocation and rebuilding are outside Milestone 1.";
    case "mutation-no-op":
      return "Remove the no-op operation or provide replacement bytes that actually differ from the guarded source bytes.";
    case "mutation-overlap":
      return "Resolve the manifest conflict so no two operations modify overlapping physical ROM bytes.";
    case "compressed-overlay-invalid":
      return "Provide a valid exact-size stored compressed-overlay replacement whose BLZ payload decodes to the canonical runtime geometry.";
    case "staging-failed":
      return "Check workspace/output permissions and source identity, then retry so RE-MCP can create a fresh controlled staging copy.";
    case "post-build-parse-failed":
    case "structural-map-changed":
      return "Revise the mutation so the rebuilt ROM preserves the canonical NDS structure and reparses successfully.";
    case "unexpected-rom-diff":
      return "Inspect the mutation plan and staged output; every changed byte must be attributable to an approved guarded operation.";
    case "output-verification-failed":
      return "Discard the invalid staged/output build and retry from the unchanged exact source after correcting the failed verification condition.";
    case "publish-collision":
      return "Inspect or remove the conflicting deterministic build directory only after preserving evidence; RE-MCP will not overwrite or repair it automatically.";
    case "publish-failed":
      return "Check the controlled output directory permissions and filesystem state, then retry without changing the source ROM.";
    case "output-bound-exceeded":
      return "Reduce the mutation manifest size or number of operations so the serialized MCP result fits the configured output limit.";
    case "invalid-rom":
    case "malformed-header":
    case "range-out-of-bounds":
    case "malformed-fat":
    case "malformed-fnt":
    case "malformed-overlay-table":
    case "unknown-file-id":
    case "unknown-overlay-id":
      return "Validate the exact NDS source and canonical selector with the static NDS inspection tools before retrying the mutation operation.";
    case "malformed-blz":
    case "blz-output-size-mismatch":
    case "blz-output-limit":
    case "compressed-overlay-runtime-unavailable":
      return "Validate the compressed overlay and its canonical runtime geometry before retrying the mutation operation.";
    default:
      return "Inspect the structured error and resolve the reported canonical NDS condition before retrying.";
  }
}

function errorResult(
  config: ServerConfig,
  operation: string,
  category: NdsServiceErrorCategory,
  error: unknown,
): MutationToolResult {
  const rawMessage = error instanceof Error ? error.message : String(error);
  return {
    content: [{
      type: "text",
      text: JSON.stringify({
        error: sanitizeMessage(config.workspaceRoot, rawMessage),
        operation,
        category,
        correctiveAction: correctiveAction(category),
      }, null, 2),
    }],
    isError: true,
  };
}

function boundedResult(
  config: ServerConfig,
  operation: string,
  value: unknown,
): MutationToolResult {
  const text = JSON.stringify(value, null, 2);
  if (Buffer.byteLength(text, "utf8") > config.maxOutputBytes) {
    return errorResult(
      config,
      operation,
      "output-bound-exceeded",
      new NdsError(
        "output-bound-exceeded",
        "Serialized mutation result would exceed RE_MCP_MAX_OUTPUT_BYTES",
      ),
    );
  }
  return { content: [{ type: "text", text }] };
}

function resolveRomPath(config: ServerConfig, requestedPath: string): string {
  try {
    return resolveInside(config.workspaceRoot, requestedPath);
  } catch (error) {
    throw new NdsError(
      "invalid-rom",
      `ROM path is not available inside the configured workspace: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

function resolveManifestPath(config: ServerConfig, requestedPath: string): string {
  try {
    return resolveInside(config.workspaceRoot, requestedPath);
  } catch (error) {
    throw new NdsError(
      "mutation-manifest-invalid",
      `Mutation manifest path is not available inside the configured workspace: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

function workspaceRelativePath(workspaceRoot: string, absolutePath: string): string {
  const resolvedRoot = path.resolve(workspaceRoot);
  const relative = path.relative(resolvedRoot, path.resolve(absolutePath));
  if (
    relative.length === 0
    || relative === ".."
    || relative.startsWith(`..${path.sep}`)
    || path.isAbsolute(relative)
  ) {
    throw new NdsError(
      "publish-failed",
      "Mutation output escaped the configured workspace",
    );
  }
  return relative.split(path.sep).join("/");
}

function publicBuildResult(
  config: ServerConfig,
  result: NdsMutationBuildResult,
): unknown {
  return {
    buildId: result.buildId,
    reused: result.reused,
    outputRoot: workspaceRelativePath(config.workspaceRoot, result.outputRoot),
    outputRomPath: workspaceRelativePath(config.workspaceRoot, result.outputRomPath),
    outputSha256: result.outputSha256,
    verification: result.verification,
  };
}

async function loadMutationInputs(
  config: ServerConfig,
  rom: string,
  manifest: string,
) {
  const romPath = resolveRomPath(config, rom);
  const manifestPath = resolveManifestPath(config, manifest);
  const map = await readNdsRomMap(romPath);
  const loadedManifest = await loadNdsMutationManifest(
    config.workspaceRoot,
    manifestPath,
  );
  return { map, loadedManifest };
}

async function runMutationTool(
  config: ServerConfig,
  operation: string,
  callback: () => Promise<unknown>,
): Promise<MutationToolResult> {
  try {
    return boundedResult(config, operation, await callback());
  } catch (error) {
    if (error instanceof NdsError) {
      return errorResult(config, operation, error.category, error);
    }
    return errorResult(
      config,
      operation,
      "publish-failed",
      error,
    );
  }
}

export function registerNdsMutationTools(
  server: McpServer,
  config: ServerConfig,
): void {
  server.tool(
    "nds_mutation_validate",
    "Validate a strict workspace-contained NDS mutation manifest against the exact source ROM without modifying or publishing anything.",
    mutationInputSchema,
    async ({ rom, manifest }) => await runMutationTool(
      config,
      "nds_mutation_validate",
      async () => {
        const { map, loadedManifest } = await loadMutationInputs(
          config,
          rom,
          manifest,
        );
        const plan = await compileNdsMutationPlan(
          map,
          config.workspaceRoot,
          loadedManifest,
        );
        return serializeResolvedNdsMutationPlan(plan);
      },
    ),
  );

  server.tool(
    "nds_mutation_build",
    "Build a verified same-size NDS mutation from a strict workspace manifest using only a controlled staged source copy.",
    mutationInputSchema,
    async ({ rom, manifest }) => await runMutationTool(
      config,
      "nds_mutation_build",
      async () => {
        const { map, loadedManifest } = await loadMutationInputs(
          config,
          rom,
          manifest,
        );
        return publicBuildResult(
          config,
          await buildNdsMutation(
            map,
            config.workspaceRoot,
            loadedManifest,
          ),
        );
      },
    ),
  );

  server.tool(
    "nds_mutation_verify",
    "Freshly revalidate the exact deterministic NDS mutation build derived from a strict workspace manifest.",
    mutationInputSchema,
    async ({ rom, manifest }) => await runMutationTool(
      config,
      "nds_mutation_verify",
      async () => {
        const { map, loadedManifest } = await loadMutationInputs(
          config,
          rom,
          manifest,
        );
        return publicBuildResult(
          config,
          await verifyPublishedNdsMutationBuild(
            map,
            config.workspaceRoot,
            loadedManifest,
          ),
        );
      },
    ),
  );
}

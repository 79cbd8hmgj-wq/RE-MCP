import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import type { ServerConfig } from "../config.js";

const mutationInputSchema = {
  rom: z.string().min(1),
  manifest: z.string().min(1),
};

function notImplemented(operation: string) {
  return {
    content: [{
      type: "text" as const,
      text: JSON.stringify({
        error: `${operation} is not implemented yet`,
        operation,
        category: "mutation-manifest-invalid",
      }, null, 2),
    }],
    isError: true,
  };
}

export function registerNdsMutationTools(
  server: McpServer,
  _config: ServerConfig,
): void {
  server.tool(
    "nds_mutation_validate",
    "Validate a strict workspace-contained NDS mutation manifest against the exact source ROM without modifying or publishing anything.",
    mutationInputSchema,
    async () => notImplemented("nds_mutation_validate"),
  );

  server.tool(
    "nds_mutation_build",
    "Build a verified same-size NDS mutation from a strict workspace manifest using only a controlled staged source copy.",
    mutationInputSchema,
    async () => notImplemented("nds_mutation_build"),
  );

  server.tool(
    "nds_mutation_verify",
    "Freshly revalidate the exact deterministic NDS mutation build derived from a strict workspace manifest.",
    mutationInputSchema,
    async () => notImplemented("nds_mutation_verify"),
  );
}

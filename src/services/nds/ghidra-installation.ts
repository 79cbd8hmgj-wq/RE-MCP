import { constants as fsConstants } from "node:fs";
import { access, readFile, stat } from "node:fs/promises";
import path from "node:path";

import type { ServerConfig } from "../../config.js";
import { resolveInside } from "../../security/paths.js";
import { NdsError } from "./errors.js";
import {
  GHIDRA_ARM7_LANGUAGE,
  GHIDRA_ARM9_LANGUAGE,
} from "./ghidra-model.js";

export interface ValidatedGhidraInstallation {
  readonly home: string;
  readonly analyzeHeadless: string;
  readonly version: string;
}

function installationError(
  category:
    | "invalid-ghidra-installation"
    | "unsupported-ghidra-version"
    | "ghidra-language-unavailable",
  message: string,
): NdsError<typeof category> {
  return new NdsError(category, message);
}

function applicationVersion(properties: string): string | null {
  const match = /^application\.version\s*=\s*([^\r\n#]+)\s*$/mu.exec(properties);
  return match?.[1]?.trim() ?? null;
}

export async function validateGhidraInstallation(
  config: ServerConfig,
): Promise<ValidatedGhidraInstallation> {
  const configuredHome = config.ghidraHome?.trim() ?? "";
  if (configuredHome.length === 0) {
    throw new NdsError(
      "ghidra-not-configured",
      "RE_MCP_GHIDRA_HOME is not configured",
    );
  }

  const home = path.resolve(configuredHome);
  const analyzeHeadless = resolveInside(home, path.join("support", "analyzeHeadless"));
  const propertiesPath = resolveInside(home, path.join("Ghidra", "application.properties"));
  const languagePath = resolveInside(
    home,
    path.join("Ghidra", "Processors", "ARM", "data", "languages", "ARM.ldefs"),
  );

  try {
    const executableInfo = await stat(analyzeHeadless);
    if (!executableInfo.isFile()) {
      throw installationError(
        "invalid-ghidra-installation",
        "Ghidra support/analyzeHeadless is not a regular file",
      );
    }
    await access(analyzeHeadless, fsConstants.X_OK);
  } catch (error) {
    if (error instanceof NdsError) throw error;
    throw installationError(
      "invalid-ghidra-installation",
      `Unable to execute Ghidra support/analyzeHeadless: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  let properties: string;
  let languages: string;
  try {
    [properties, languages] = await Promise.all([
      readFile(propertiesPath, "utf8"),
      readFile(languagePath, "utf8"),
    ]);
  } catch (error) {
    throw installationError(
      "invalid-ghidra-installation",
      `Ghidra installation metadata is unavailable: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  const version = applicationVersion(properties);
  if (version === null || !/^12\./u.test(version)) {
    throw installationError(
      "unsupported-ghidra-version",
      `RE-MCP requires a supported Ghidra 12.x installation; found ${version ?? "unknown version"}`,
    );
  }

  const missing = [GHIDRA_ARM9_LANGUAGE, GHIDRA_ARM7_LANGUAGE]
    .filter((id) => !languages.includes(`id="${id}"`));
  if (missing.length > 0) {
    throw installationError(
      "ghidra-language-unavailable",
      `Configured Ghidra installation is missing required language(s): ${missing.join(", ")}`,
    );
  }

  return { home, analyzeHeadless, version };
}

import path from "node:path";

export type BakuganQualityStage = "compile" | "ruff" | "mypy" | "tests" | "full";

const QUALITY_COMMANDS: Readonly<Record<Exclude<BakuganQualityStage, "full">, readonly string[]>> = {
  compile: ["-m", "compileall", "-q", "src", "tests", "tools"],
  ruff: ["-m", "ruff", "check", "."],
  mypy: ["-m", "mypy"],
  tests: ["-m", "pytest", "-q"],
};

export function qualityStages(stage: BakuganQualityStage): readonly Exclude<BakuganQualityStage, "full">[] {
  return stage === "full" ? ["compile", "ruff", "mypy", "tests"] : [stage];
}

export function qualityCommand(stage: Exclude<BakuganQualityStage, "full">): readonly string[] {
  return QUALITY_COMMANDS[stage];
}

export function assertGeneratedAnalysisPath(projectRoot: string, outputPath: string): string {
  const generatedRoot = path.join(projectRoot, "analysis", "generated");
  const resolved = path.resolve(projectRoot, outputPath);
  const relative = path.relative(generatedRoot, resolved);
  if (relative.length === 0 || relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error("Roster reports must be written to a file under analysis/generated");
  }
  return resolved;
}

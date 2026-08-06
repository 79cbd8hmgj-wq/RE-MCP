import path from "node:path";

export function resolveInside(root: string, requestedPath: string): string {
  if (requestedPath.includes("\0")) {
    throw new Error("Path contains a NUL byte");
  }

  const resolvedRoot = path.resolve(root);
  const resolvedPath = path.resolve(resolvedRoot, requestedPath);
  const relative = path.relative(resolvedRoot, resolvedPath);

  if (relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative))) {
    return resolvedPath;
  }

  throw new Error(`Path escapes workspace root: ${requestedPath}`);
}

export function assertSimpleProjectName(project: string): string {
  if (!/^[A-Za-z0-9._-]+$/.test(project) || project === "." || project === "..") {
    throw new Error("Project name may contain only letters, numbers, dot, underscore, and hyphen");
  }
  return project;
}

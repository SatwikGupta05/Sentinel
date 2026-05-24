import { PackageScan } from '../scanner/types';

/**
 * Parse a yarn.lock (v1) file and extract npm package names and resolved versions.
 *
 * Yarn lockfile format:
 *   package-name@^1.0.0:
 *     version "1.2.3"
 *     resolved "https://..."
 *     integrity sha1-...
 *     dependencies:
 *       dep "^2.0.0"
 *
 * For scoped packages:
 *   "@scope/name@^1.0.0":
 *     version "1.2.3"
 */
export function parseYarnLock(content: string): PackageScan[] {
  const packageMap = new Map<string, string>();
  const lines = content.split('\n');

  let currentPkgKey: string | null = null;
  let currentVersion: string | null = null;

  for (const rawLine of lines) {
    // Preserve leading whitespace to determine nesting
    const trimmedStart = rawLine.trimStart();
    const indent = rawLine.length - trimmedStart.length;
    const line = trimmedStart.trimEnd();

    // Skip empty, comment lines, and file header
    if (!line || line.startsWith('#') || line.startsWith('//')) continue;

    if (indent === 0) {
      // Save previous entry
      saveEntry(currentPkgKey, currentVersion, packageMap);

      // New entry header: "package@^1.0.0:" or "pkg@1.0.0, pkg@^2.0.0:"
      if (line.endsWith(':')) {
        currentPkgKey = line.slice(0, -1).trim();
        currentVersion = null;
      } else {
        currentPkgKey = null;
        currentVersion = null;
      }
    } else if (currentPkgKey && indent > 0) {
      // Parse version line within entry
      const versionMatch = line.match(/^version\s+"([^"]+)"/);
      if (versionMatch) {
        currentVersion = versionMatch[1];
      }
    }
  }

  // Save last entry
  saveEntry(currentPkgKey, currentVersion, packageMap);

  return Array.from(packageMap.entries()).map(([name, version]) => ({
    name,
    new_version: version,
    registry: 'npm' as const,
  }));
}

function saveEntry(
  key: string | null,
  version: string | null,
  map: Map<string, string>
): void {
  if (!key || !version) return;

  const name = extractPackageName(key);
  if (name && !map.has(name)) {
    map.set(name, version);
  }
}

/**
 * Extract the package name from a yarn.lock entry key.
 *
 * Examples:
 *   "lodash@^4.0.0"             → "lodash"
 *   "\"@babel/core@^7.0.0\""   → "@babel/core"
 *   "typescript"                → "typescript"
 *   "\"@scope/name@^1.0.0, @scope/name@^1.2.0\""  → "@scope/name"
 */
function extractPackageName(key: string): string | null {
  // Remove surrounding quotes
  let cleaned = key.replace(/"/g, '').trim();

  // If multiple entries separated by comma, take the first one
  const commaIdx = cleaned.indexOf(',');
  if (commaIdx !== -1) {
    cleaned = cleaned.substring(0, commaIdx).trim();
  }

  if (!cleaned) return null;

  // For scoped packages like @scope/name@version
  if (cleaned.startsWith('@')) {
    const atIdx = cleaned.indexOf('@', 1);
    if (atIdx === -1) return cleaned; // just @scope/name with no range
    return cleaned.substring(0, atIdx);
  }

  // For regular packages
  const atIdx = cleaned.indexOf('@');
  if (atIdx === -1) return cleaned; // just name with no range
  return cleaned.substring(0, atIdx);
}

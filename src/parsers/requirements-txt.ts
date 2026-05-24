import { PackageScan } from '../scanner/types';

/**
 * Parse a Python requirements.txt file and extract PyPI package names and versions.
 *
 * Format examples:
 *   requests==2.28.0
 *   flask>=2.0,<3.0
 *   numpy
 *   django~=4.2.0
 *   package[extra1,extra2]>=1.0
 *   # comment
 *   -e git+https://...
 *   --index-url https://...
 */
export function parseRequirementsTxt(content: string): PackageScan[] {
  const packages: PackageScan[] = [];
  const seen = new Set<string>();
  const lines = content.split('\n');

  for (const rawLine of lines) {
    const trimmed = rawLine.trim();

    // Skip empty lines, comments, and option flags
    if (!trimmed) continue;
    if (trimmed.startsWith('#')) continue;
    if (trimmed.startsWith('-')) continue;
    if (trimmed.startsWith('--')) continue;
    if (trimmed.startsWith('[')) continue; // unlikely but guard

    // Remove inline comments
    const noComment = trimmed.split(' #')[0].trim();
    if (!noComment) continue;

    // Remove extras like package[security] → package
    const strippedExtras = noComment.replace(/\[.*?\]/g, '').trim();
    if (!strippedExtras) continue;

    // Remove environment markers: package==1.0 ; python_version >= "3.7"
    const noMarker = strippedExtras.split(';')[0].trim();
    if (!noMarker) continue;

    // Match package name and optional version specifier
    // Package names: alphanumeric, dots, hyphens, underscores
    // Version specifiers: ==, >=, <=, >, <, ~=, !=
    const match = noMarker.match(
      /^([a-zA-Z0-9][a-zA-Z0-9_.-]*[a-zA-Z0-9]|[a-zA-Z0-9])\s*(?:([><=!~]+)\s*([a-zA-Z0-9_.*]+(?:\s*,\s*[><=!~]+\s*[a-zA-Z0-9_.*]+)*))?/
    );
    if (!match) continue;

    const name = match[1];
    const operator = match[2];
    const versionSpec = match[3];

    // Normalize name: PyPI treats hyphens, underscores, and dots as equivalent
    const normalizedName = name.replace(/[-_.]+/g, '-').toLowerCase();

    if (seen.has(normalizedName)) continue;
    seen.add(normalizedName);

    let newVersion: string | undefined;

    if (operator === '==' && versionSpec) {
      // Exact version: requests==2.28.0
      newVersion = versionSpec.trim();
    } else if (operator && versionSpec) {
      // For non-exact specs like >=2.0, <3.0, just record the first constraint
      const firstSpec = versionSpec.split(',')[0].trim();
      const specMatch = firstSpec.match(/^[><=!~]+\s*([a-zA-Z0-9_.*]+)/);
      if (specMatch) {
        const ver = specMatch[1].replace(/\*/g, '0');
        newVersion = ver;
      }
    }

    packages.push({
      name: normalizedName,
      new_version: newVersion,
      registry: 'pypi',
    });
  }

  return packages;
}

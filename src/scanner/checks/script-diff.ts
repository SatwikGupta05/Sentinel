import { PackageScan, CheckResult } from '../types';
import zlib from 'zlib';

/**
 * Check 1: Script Diff Analysis
 * Compares install scripts between old and new package versions
 * to detect malicious code injection in build hooks.
 *
 * For npm: compares install scripts between versions.
 * For PyPI: checks setup.py/pyproject.toml for suspicious build hooks.
 */
export async function checkScriptDiff(pkg: PackageScan): Promise<CheckResult> {
  const { name, old_version, new_version, registry } = pkg;

  // For PyPI packages, do a basic check on the sdist for suspicious setup hooks
  if (registry === 'pypi') {
    return checkPypiScriptDiff(name, new_version);
  }

  try {
    // Fetch package metadata from npm registry with timeout
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30000);
    let response;
    try {
      response = await fetch(`https://registry.npmjs.org/${encodeURIComponent(name)}`, { signal: controller.signal });
    } finally {
      clearTimeout(timeout);
    }
    if (!response.ok) {
      return {
        check_type: 'script_diff',
        severity: 'info',
        message: `${name}: Could not fetch package metadata (${response.status})`,
        details: { error: `HTTP ${response.status}` },
      };
    }

    const data = await response.json() as Record<string, unknown>;
    const versions = data.versions as Record<string, { scripts?: Record<string, string> }> | undefined;

    if (!versions) {
      return {
        check_type: 'script_diff',
        severity: 'info',
        message: `${name}: No version data available`,
      };
    }

    // Get scripts from old and new versions
    const oldScripts = old_version && versions[old_version]?.scripts;
    const newScripts = new_version && versions[new_version]?.scripts;

    if (!oldScripts && !newScripts) {
      return {
        check_type: 'script_diff',
        severity: 'info',
        message: `${name}: No install scripts detected ✓`,
      };
    }

    // If no old version (new package), check if scripts exist
    if (!old_version && newScripts) {
      const suspiciousScripts = findSuspiciousScripts(newScripts);
      if (suspiciousScripts.length > 0) {
        return {
          check_type: 'script_diff',
          severity: 'critical',
          message: `${name}: New package with suspicious install scripts detected!`,
          details: { suspiciousScripts },
        };
      }
      return {
        check_type: 'script_diff',
        severity: 'info',
        message: `${name}: Install scripts present but no obvious malicious patterns`,
        details: { scripts: newScripts },
      };
    }

    if (!oldScripts && newScripts) {
      // Scripts were added in the new version
      const suspiciousScripts = findSuspiciousScripts(newScripts);
      if (suspiciousScripts.length > 0) {
        return {
          check_type: 'script_diff',
          severity: 'critical',
          message: `${name}: New malicious install scripts detected in version ${new_version}!`,
          details: { suspiciousScripts, newScripts },
        };
      }
      return {
        check_type: 'script_diff',
        severity: 'warning',
        message: `${name}: New install scripts added in version ${new_version}`,
        details: { scripts: newScripts },
      };
    }

    // Compare old vs new scripts
    if (oldScripts && newScripts) {
      const changedHooks: string[] = [];
      const newHooks: string[] = [];
      const allHooks = new Set([...Object.keys(oldScripts), ...Object.keys(newScripts)]);

      for (const hook of allHooks) {
        if (!oldScripts[hook] && newScripts[hook]) {
          newHooks.push(hook);
        } else if (oldScripts[hook] !== newScripts[hook]) {
          changedHooks.push(hook);
        }
      }

      if (newHooks.length > 0 || changedHooks.length > 0) {
        const allChanged = [...newHooks, ...changedHooks];
        const suspiciousScripts = findSuspiciousScripts(
          Object.fromEntries(allChanged.map(h => [h, newScripts[h]]))
        );

        if (suspiciousScripts.length > 0) {
          return {
            check_type: 'script_diff',
            severity: 'critical',
            message: `${name}: Malicious changes detected in install scripts!`,
            details: { suspiciousScripts, changedScripts: allChanged },
          };
        }
        return {
          check_type: 'script_diff',
          severity: 'warning',
          message: `${name}: Install scripts modified in version ${new_version}`,
          details: { changedScripts: allChanged },
        };
      }
    }

    return {
      check_type: 'script_diff',
      severity: 'info',
      message: `${name}: No script changes detected ✓`,
    };
  } catch (error) {
    return {
      check_type: 'script_diff',
      severity: 'warning',
      message: `${name}: Error analyzing scripts: ${(error as Error).message}`,
      details: { error: String(error) },
    };
  }
}

const MALICIOUS_PATTERNS = [
  /curl\s+\S*\s*\|\s*(bash|sh)/i,
  /wget\s+\S*\s*\|\s*(bash|sh)/i,
  /base64.*-d\s*\|\s*(bash|sh)/i,
  /eval\s*\(/i,
  /child_process/i,
  /exec\s*\(/i,
  /spawn\s*\(/i,
  /process\.env/i,
  /dns\.lookup/i,
  /dns\.resolve/i,
  /fs\.readFileSync\s*\(\s*['"`]~\/\./i,
  /\.npmrc/i,
  /\.env/i,
  /crypto\.miner/i,
  /xmr/i,
  /monero/i,
  /http\.request.*localhost/i,
  /process\.binding/i,
  /require\s*\(\s*['"`]child_process['"`]/i,
  /fetch\s*\(['"`]https?:\/\//i,
];

// ─── PyPI Script Diff ────────────────────────────────────────────

/**
 * For PyPI packages, check the sdist for suspicious setup.py/pyproject.toml hooks.
 * Python packages don't have "install scripts" like npm, but they can have
 * setup.py with cmdclass that runs arbitrary code during installation.
 */
async function checkPypiScriptDiff(
  name: string,
  version?: string
): Promise<CheckResult> {
  try {
    // PyPI JSON API does NOT support /latest/ — use unversioned endpoint for latest
    const url = version
      ? `https://pypi.org/pypi/${encodeURIComponent(name)}/${encodeURIComponent(version)}/json`
      : `https://pypi.org/pypi/${encodeURIComponent(name)}/json`;
    const pypiController = new AbortController();
    const pypiTimeout = setTimeout(() => pypiController.abort(), 30000);
    let response;
    try {
      response = await fetch(url, { signal: pypiController.signal });
    } finally {
      clearTimeout(pypiTimeout);
    }
    if (!response.ok) {
      return {
        check_type: 'script_diff',
        severity: 'info',
        message: `${name}: Could not fetch PyPI metadata (${response.status})`,
        details: { error: `HTTP ${response.status}` },
      };
    }

    const data = await response.json() as {
      info: { name: string; version?: string };
      urls?: { filename: string; url: string; packagetype: string }[];
      releases?: Record<string, { filename: string; url: string; packagetype: string }[]>;
    };

    // Use the actual version from response metadata when no specific version requested
    const actualVersion = version || data.info.version || '';

    // Find the source distribution URL
    const sdistUrl = findSdistUrl(data, actualVersion);
    if (!sdistUrl) {
      return {
        check_type: 'script_diff',
        severity: 'info',
        message: `${name}: No source distribution available to scan ✓`,
      };
    }

    // Download the sdist (.tar.gz) with timeout
    const sdistController = new AbortController();
    const sdistTimeout = setTimeout(() => sdistController.abort(), 60000);
    let sdistResponse;
    try {
      sdistResponse = await fetch(sdistUrl, { signal: sdistController.signal });
    } finally {
      clearTimeout(sdistTimeout);
    }
    if (!sdistResponse.ok) {
      return {
        check_type: 'script_diff',
        severity: 'info',
        message: `${name}: Could not download source distribution`,
        details: { error: `HTTP ${sdistResponse.status}` },
      };
    }

    const buffer = Buffer.from(await sdistResponse.arrayBuffer());

    try {
      const decompressed = zlib.gunzipSync(buffer);
      const content = decompressed.toString('utf-8');

      // Look for suspicious patterns in setup.py/pyproject.toml/setup.cfg content
      const suspicious: string[] = [];
      const PYPI_SUSPICIOUS_PATTERNS = [
        // Only truly malicious patterns — os.system, subprocess, cmdclass are NORMAL in Python build scripts
        { pattern: /curl\s+\S*\s*\|\s*(bash|sh)/i, label: 'curl-to-bash execution' },
        { pattern: /wget\s+\S*\s*\|\s*(bash|sh)/i, label: 'wget-to-bash execution' },
        { pattern: /base64.*-d\s*\|\s*(bash|sh)/i, label: 'base64 decode execution' },
      ];

      for (const { pattern, label } of PYPI_SUSPICIOUS_PATTERNS) {
        if (pattern.test(content)) {
          suspicious.push(label);
        }
      }

      if (suspicious.length > 0) {
        return {
          check_type: 'script_diff',
          severity: 'critical',
          message: `${name}: Suspicious patterns detected in PyPI package setup!`,
          details: { suspicious },
        };
      }

      return {
        check_type: 'script_diff',
        severity: 'info',
        message: `${name}: No suspicious setup hooks detected ✓`,
      };
    } catch {
      return {
        check_type: 'script_diff',
        severity: 'info',
        message: `${name}: Could not decompress source distribution for analysis`,
      };
    }
  } catch (error) {
    return {
      check_type: 'script_diff',
      severity: 'info',
      message: `${name}: Skipped script analysis: ${(error as Error).message}`,
      details: { error: String(error) },
    };
  }
}

/**
 * Find the source distribution URL from PyPI package data.
 * Prefers sdist, falls back to any .tar.gz URL.
 */
function findSdistUrl(
  data: {
    urls?: { filename: string; url: string; packagetype: string }[];
    releases?: Record<string, { filename: string; url: string; packagetype: string }[]>;
  },
  version: string
): string | null {
  // Check current version's urls first
  if (data.urls) {
    const sdist = data.urls.find(u => u.packagetype === 'sdist');
    if (sdist) return sdist.url;
    // Fallback to any .tar.gz
    const tar = data.urls.find(u => u.filename.endsWith('.tar.gz'));
    if (tar) return tar.url;
  }

  // Check releases for the specific version
  if (data.releases && data.releases[version]) {
    const files = data.releases[version];
    const sdist = files.find(f => f.packagetype === 'sdist');
    if (sdist) return sdist.url;
    const tar = files.find(f => f.filename.endsWith('.tar.gz'));
    if (tar) return tar.url;
  }

  return null;
}

function findSuspiciousScripts(scripts: Record<string, string>): string[] {
  const suspicious: string[] = [];
  for (const [hook, script] of Object.entries(scripts)) {
    for (const pattern of MALICIOUS_PATTERNS) {
      if (pattern.test(script)) {
        suspicious.push(`${hook}: ${script.substring(0, 100)}`);
        break;
      }
    }
  }
  return suspicious;
}

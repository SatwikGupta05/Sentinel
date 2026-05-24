import { PackageScan, CheckResult } from '../types';
import zlib from 'zlib';

/**
 * Check 2: Code Analysis
 * Scans package source code for suspicious patterns like credential theft,
 * data exfiltration, clipboard hijacking, and obfuscated payloads.
 *
 * For npm: fetches the tarball from npm registry.
 * For PyPI: fetches the sdist from PyPI.
 * Scans decompressed source for security-relevant patterns.
 */
export async function checkCodeAnalysis(pkg: PackageScan): Promise<CheckResult> {
  const { name, new_version, registry } = pkg;

  if (registry === 'pypi') {
    return checkPypiCodeAnalysis(name, new_version);
  }

  try {
    // Fetch the package tarball
    const response = await fetch(`https://registry.npmjs.org/${encodeURIComponent(name)}/${new_version || 'latest'}`);
    if (!response.ok) {
      return {
        check_type: 'code_analysis',
        severity: 'info',
        message: `${name}: Could not fetch package version data (${response.status})`,
        details: { error: `HTTP ${response.status}` },
      };
    }

    const data = await response.json() as { dist?: { tarball?: string } };
    const tarballUrl = data.dist?.tarball;

    if (!tarballUrl) {
      return {
        check_type: 'code_analysis',
        severity: 'info',
        message: `${name}: No tarball URL available for analysis`,
      };
    }

    // Download the tarball
    const tarballResponse = await fetch(tarballUrl);
    if (!tarballResponse.ok) {
      return {
        check_type: 'code_analysis',
        severity: 'info',
        message: `${name}: Could not download package tarball`,
        details: { error: `HTTP ${tarballResponse.status}` },
      };
    }

    const tarballBuffer = Buffer.from(await tarballResponse.arrayBuffer());

    // Decompress the gzipped tarball and scan for patterns
    const findings = analyzePackageContent(tarballBuffer);

    if (findings.critical.length > 0) {
      return {
        check_type: 'code_analysis',
        severity: 'critical',
        message: `${name}: Critical security patterns detected in source code!`,
        details: {
          criticalFindings: findings.critical,
          warnings: findings.warnings,
        },
      };
    }

    if (findings.warnings.length > 0) {
      return {
        check_type: 'code_analysis',
        severity: 'warning',
        message: `${name}: Suspicious patterns found that may require review`,
        details: { warnings: findings.warnings },
      };
    }

    return {
      check_type: 'code_analysis',
      severity: 'info',
      message: `${name}: No suspicious patterns detected ✓`,
    };
  } catch (error) {
    return {
      check_type: 'code_analysis',
      severity: 'warning',
      message: `${name}: Error during code analysis: ${(error as Error).message}`,
      details: { error: String(error) },
    };
  }
}

interface AnalysisFindings {
  critical: string[];
  warnings: string[];
}

function analyzePackageContent(tarballBuffer: Buffer): AnalysisFindings {
  const findings: AnalysisFindings = { critical: [], warnings: [] };

  try {
    // Decompress the gzipped tarball
    const decompressed = zlib.gunzipSync(tarballBuffer);
    // Convert to string - tar files contain text content mixed with binary headers
    // but the JS source code we care about will be readable as UTF-8
    const content = decompressed.toString('utf-8');

    // Split into lines for file-level analysis
    const lines = content.split('\n');

    // Scan each line for patterns
    let currentFile = 'unknown';

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Detect file paths in tar output (starts with package/something.js)
      if (line.startsWith('package/') && (line.endsWith('.js') || line.endsWith('.ts') || line.endsWith('.mjs'))) {
        currentFile = line.trim().replace(/\0/g, '');
        continue;
      }

      // Skip tar header lines (typically 512-byte binary headers, not useful as text)
      if (line.length === 512 && /^.{156}[^\0]{0,100}/.test(line)) {
        continue;
      }

      // Check for critical patterns
      for (const { pattern, label } of CRITICAL_PATTERNS) {
        if (pattern.test(line)) {
          findings.critical.push(`${currentFile} (line ~${i}): ${label}`);
        }
      }

      // Check for warning patterns
      for (const { pattern, label } of WARNING_PATTERNS) {
        if (pattern.test(line)) {
          findings.warnings.push(`${currentFile}: ${label}`);
        }
      }
    }
  } catch (error) {
    // If standard decompression fails, try raw content scan
    try {
      scanRawContent(tarballBuffer, findings);
    } catch {
      findings.warnings.push('Could not decompress or scan package content');
    }
  }

  return findings;
}

interface PatternEntry {
  pattern: RegExp;
  label: string;
}

const CRITICAL_PATTERNS: PatternEntry[] = [
  // Obfuscated code execution — almost always malicious
  { pattern: /eval\s*\(\s*atob/, label: 'Obfuscated eval with base64' },
  { pattern: /eval\s*\(\s*Buffer\.from\s*\(/, label: 'Obfuscated eval with Buffer' },
  // curl/wget piped to shell — always malicious
  { pattern: /curl\s+\S+\s*\|\s*(?:bash|sh)\b/i, label: 'curl-to-bash execution' },
  { pattern: /wget\s+\S+\s*\|\s*(?:bash|sh)\b/i, label: 'wget-to-bash execution' },
  // Base64 decode piped to shell — always malicious
  { pattern: /base64.*-d\s*\|\s*(?:bash|sh)/i, label: 'Base64 decode piped to shell' },
  // Crypto transaction interception (very specific RPC method)
  { pattern: /eth_sendTransaction/, label: 'Crypto transaction interception' },
];

const WARNING_PATTERNS: PatternEntry[] = [
  // Sensitive module usage
  { pattern: /require\s*\(\s*['"`]child_process/, label: 'Child process module' },
  { pattern: /require\s*\(\s*['"`]net['"`]/, label: 'Network module' },
  { pattern: /require\s*\(\s*['"`]dns['"`]/, label: 'DNS module' },
  { pattern: /new\s+Function\s*\(/, label: 'Dynamic code execution' },
  // Environment variable access
  { pattern: /process\.env\s*\[?\s*['"`]?(?:API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)/i, label: 'Credential environment variable access' },
  // Network resolution
  { pattern: /dns\.lookup|dns\.resolve/, label: 'DNS resolution' },
  // Browser-specific sensitive APIs (flagged in npm packages which run in Node)
  { pattern: /navigator\.clipboard/, label: 'Clipboard access' },
  { pattern: /window\.ethereum/, label: 'Web3 wallet interaction' },
];

function scanRawContent(content: string | Buffer, findings: AnalysisFindings): void {
  if (Buffer.isBuffer(content)) {
    content = content.toString('utf-8');
  }
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const { pattern, label } of CRITICAL_PATTERNS) {
      if (pattern.test(line)) {
        findings.critical.push(`Raw line ${i}: ${label}`);
        break;
      }
    }
  }
}

// ─── PyPI Code Analysis ──────────────────────────────────────────

/**
 * PyPI variant: fetches the source distribution from PyPI,
 * extracts it, and scans for Python-specific suspicious patterns
 * plus the general ones that overlap with npm (e.g. crypto addresses,
 * HTTP exfiltration, credential access).
 */
async function checkPypiCodeAnalysis(
  name: string,
  version?: string
): Promise<CheckResult> {
  try {
    // PyPI JSON API does NOT support /latest/ — use unversioned endpoint for latest
    const url = version
      ? `https://pypi.org/pypi/${encodeURIComponent(name)}/${encodeURIComponent(version)}/json`
      : `https://pypi.org/pypi/${encodeURIComponent(name)}/json`;
    const response = await fetch(url);
    if (!response.ok) {
      return {
        check_type: 'code_analysis',
        severity: 'info',
        message: `${name}: Could not fetch PyPI package data (${response.status})`,
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

    // Find the sdist URL
    let sdistUrl: string | null = null;
    if (data.urls) {
      const sdist = data.urls.find(u => u.packagetype === 'sdist');
      if (sdist) sdistUrl = sdist.url;
      else {
        const tar = data.urls.find(u => u.filename.endsWith('.tar.gz'));
        if (tar) sdistUrl = tar.url;
      }
    }
    if (!sdistUrl && data.releases && data.releases[actualVersion]) {
      const sdist = data.releases[actualVersion].find(f => f.packagetype === 'sdist');
      if (sdist) sdistUrl = sdist.url;
    }

    if (!sdistUrl) {
      return {
        check_type: 'code_analysis',
        severity: 'info',
        message: `${name}: No source distribution available for analysis`,
      };
    }

    // Download the sdist with timeout (large packages like numpy can be 50MB+)
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 60000);
    let sdistRes;
    try {
      sdistRes = await fetch(sdistUrl, { signal: controller.signal });
    } finally {
      clearTimeout(timeout);
    }
    if (!sdistRes.ok) {
      return {
        check_type: 'code_analysis',
        severity: 'info',
        message: `${name}: Could not download source distribution`,
        details: { error: `HTTP ${sdistRes.status}` },
      };
    }

    const buffer = Buffer.from(await sdistRes.arrayBuffer());
    const findings = analyzePypiContent(buffer);

    if (findings.critical.length > 0) {
      return {
        check_type: 'code_analysis',
        severity: 'critical',
        message: `${name}: Critical security patterns detected in Python source code!`,
        details: {
          criticalFindings: findings.critical,
          warnings: findings.warnings,
        },
      };
    }

    if (findings.warnings.length > 0) {
      return {
        check_type: 'code_analysis',
        severity: 'warning',
        message: `${name}: Suspicious patterns found that may require review`,
        details: { warnings: findings.warnings },
      };
    }

    return {
      check_type: 'code_analysis',
      severity: 'info',
      message: `${name}: No suspicious patterns detected ✓`,
    };
  } catch (error) {
    return {
      check_type: 'code_analysis',
      severity: 'warning',
      message: `${name}: Error during PyPI code analysis: ${(error as Error).message}`,
      details: { error: String(error) },
    };
  }
}

/**
 * PyPI-specific suspicious patterns for Python source code.
 * Narrowed to only genuinely malicious activities — standard library
 * usage (subprocess, requests, socket, os.environ, etc.) is common in
 * legitimate Python packages and should NOT be flagged.
 */
const PYPI_CRITICAL_PATTERNS: PatternEntry[] = [
  // Obfuscated execution: base64 payload being executed (not just decoded)
  { pattern: /exec\s*\(\s*base64/, label: 'Obfuscated exec with base64' },
  { pattern: /eval\s*\(\s*base64/, label: 'Obfuscated eval with base64' },
  { pattern: /compile\s*\([^)]*,\s*['"`]<(?:stdin|string)>['"`],\s*['"`]exec['"`]\s*\)/, label: 'Compiled code execution (obfuscation)' },
  { pattern: /base64.*-d\s*\|\s*(?:bash|sh)/i, label: 'Base64 decode piped to shell' },
  // curl/wget to bash (always malicious)
  { pattern: /curl\s+\S+\s*\|\s*(?:bash|sh)\b/i, label: 'curl-to-bash execution' },
  { pattern: /wget\s+\S+\s*\|\s*(?:bash|sh)\b/i, label: 'wget-to-bash execution' },
  // Crypto wallet transaction interception
  { pattern: /eth_sendTransaction/, label: 'Crypto transaction interception' },
  // Credential exfiltration (sending credentials to external URLs in same line)
  { pattern: /os\.environ\s*[^)]*\s*\).*https?:\/\//, label: 'Potential credential exfiltration' },
];

const PYPI_WARNING_PATTERNS: PatternEntry[] = [
  // Unsafe deserialization (only marshal - pickle is too common in tests)
  { pattern: /marshal\.(?:load|dumps)/, label: 'Marshal deserialization' },
  // Hardcoded crypto addresses
  { pattern: /to\s*=\s*['"`]?0x[a-fA-F0-9]{40}['"`]?/, label: 'Hardcoded crypto address' },
  // Crypto wallet interaction
  { pattern: /web3\.eth/, label: 'Web3.py interaction' },
  // Native code loading
  { pattern: /ctypes\.(?:CDLL|cdll|util)/, label: 'Native code loading (ctypes)' },
];

function analyzePypiContent(buffer: Buffer): AnalysisFindings {
  const findings: AnalysisFindings = { critical: [], warnings: [] };

  try {
    const decompressed = zlib.gunzipSync(buffer);
    const content = decompressed.toString('utf-8');
    const lines = content.split('\n');
    let currentFile = 'unknown';

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Detect Python file paths in tar (starts with package-name/...)
      // and also detect setup.py, pyproject.toml, etc.
      if (line.includes('/') && (line.endsWith('.py') || line.endsWith('.toml') || line.endsWith('.cfg'))) {
        const trimmed = line.trim().replace(/\0/g, '');
        if (trimmed.startsWith('/') || /^[^\s]+\/[^\s]+\.(py|toml|cfg)$/.test(trimmed)) {
          currentFile = trimmed;
          continue;
        }
      }

      // Skip tar header lines
      if (line.length === 512 && /^.{156}[^\0]{0,100}/.test(line)) {
        continue;
      }

      // Check for critical patterns
      for (const { pattern, label } of PYPI_CRITICAL_PATTERNS) {
        if (pattern.test(line)) {
          findings.critical.push(`${currentFile} (line ~${i}): ${label}`);
        }
      }

      // Check for warning patterns
      for (const { pattern, label } of PYPI_WARNING_PATTERNS) {
        if (pattern.test(line)) {
          findings.warnings.push(`${currentFile}: ${label}`);
        }
      }
    }
  } catch {
    findings.warnings.push('Could not decompress or scan PyPI package content');
  }

  return findings;
}

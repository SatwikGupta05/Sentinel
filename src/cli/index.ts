#!/usr/bin/env node

import dotenv from 'dotenv';
import { Command } from 'commander';
import fs from 'fs';
import path from 'path';

// Load .env file from current working directory
dotenv.config();
import { scanPackages } from '../scanner/index';
import { PackageScan, Verdict } from '../scanner/types';
import { parseYarnLock } from '../parsers/yarn-lock';
import { parseRequirementsTxt } from '../parsers/requirements-txt';

const program = new Command();

program
  .name('sentinel')
  .description('🛡️ Supply Chain Security Guardian - Check packages for malicious code')
  .version('1.0.0');

program
  .command('check-all')
  .description('Scan all dependencies in package.json, yarn.lock, or requirements.txt')
  .option('-p, --path <path>', 'Path to project directory', '.')
  .option('--api <url>', 'Sentinel API URL (if using remote scanning)')
  .option('--key <key>', 'Sentinel API key')
  .action(async (options) => {
    await runCheckAll(options);
  });

program
  .command('check <package-name>')
  .description('Scan a single package')
  .option('--version <version>', 'Package version to scan')
  .option('--registry <registry>', 'Package registry (npm or pypi)', 'npm')
  .action(async (packageName, options) => {
    const pkg: PackageScan = {
      name: packageName,
      new_version: options.version,
      registry: options.registry === 'pypi' ? 'pypi' : 'npm',
    };
    const geminiKey = process.env.GEMINI_API_KEY;
    const result = await scanPackages([pkg], geminiKey);
    printResults(result.results, result.overallVerdict, result.overallConfidence, result.summary);
  });

program
  .command('init')
  .description('Initialize Sentinel in the current project')
  .action(() => {
    console.log(`
🛡️  Sentinel - Project Initialization

To set up Sentinel for this project:

1. Run:  npx sentinel check-all
2. Review the scan results
3. Install packages if all are safe
4. (Optional) Add to CI: see https://sentinel.dev/docs

Supported manifests:
  • package.json    — npm dependencies
  • yarn.lock       — yarn dependencies (npm packages)
  • requirements.txt — Python pip dependencies

For more info: https://sentinel.dev
`);
  });

program.parse(process.argv);

interface ManifestSource {
  type: 'npm' | 'pypi' | 'yarn';
  path: string;
  packages: PackageScan[];
}

async function runCheckAll(options: { path: string; api?: string; key?: string }) {
  const projectPath = path.resolve(options.path);

  console.log(`
🛡️  Sentinel Security Scan
━━━━━━━━━━━━━━━━━━━━━━━━━
`);

  // Detect all manifest files
  const manifestSources = detectManifests(projectPath);

  if (manifestSources.length === 0) {
    console.error('❌ No supported manifest files found.');
    console.log('\nLooked for: package.json, yarn.lock, requirements.txt');
    console.log('Run this command in a directory with one of these files.');
    process.exit(1);
  }

  // Collect all packages, dedup by name
  const allPackages: PackageScan[] = [];
  const seenNames = new Map<string, PackageScan>();

  for (const source of manifestSources) {
    for (const pkg of source.packages) {
      const key = `${pkg.registry || 'npm'}:${pkg.name}`;
      if (!seenNames.has(key)) {
        seenNames.set(key, pkg);
        allPackages.push(pkg);
      }
    }
  }

  if (allPackages.length === 0) {
    console.log('No dependencies found in any manifest file.');
    return;
  }

  // Print what was discovered (grouped by type)
  const grouped = new Map<string, { files: number; packages: number }>();
  for (const source of manifestSources) {
    if (source.packages.length === 0) continue;
    const label = {
      npm: 'package.json',
      yarn: 'yarn.lock',
      pypi: 'requirements.txt',
    }[source.type];
    const entry = grouped.get(label) || { files: 0, packages: 0 };
    entry.files++;
    entry.packages += source.packages.length;
    grouped.set(label, entry);
  }
  for (const [label, { files, packages }] of grouped) {
    if (files === 1) {
      console.log(`📄 Found ${packages} packages in ${label}`);
    } else {
      console.log(`📄 Found ${packages} packages across ${files} ${label} files`);
    }
  }
  console.log(`\n🔍 Scanning ${allPackages.length} unique packages...\n`);

  // Count by ecosystem
  const npmCount = allPackages.filter(p => p.registry !== 'pypi').length;
  const pypiCount = allPackages.filter(p => p.registry === 'pypi').length;
  if (npmCount > 0) console.log(`   npm packages: ${npmCount}`);
  if (pypiCount > 0) console.log(`   PyPI packages: ${pypiCount}`);
  console.log('');

  try {
    const geminiKey = process.env.GEMINI_API_KEY;
    const result = await scanPackages(allPackages, geminiKey);

    printResults(result.results, result.overallVerdict, result.overallConfidence, result.summary);
  } catch (error) {
    console.error(`❌ Error: ${(error as Error).message}`);
    process.exit(1);
  }
}

/**
 * Resolve npm workspace patterns to actual directories.
 * Handles both direct paths ("frontend") and simple globs ("packages/*").
 */
function resolveWorkspacePatterns(projectPath: string, patterns: string[]): string[] {
  const dirs: string[] = [];
  for (const pattern of patterns) {
    if (pattern.includes('*')) {
      // Simple glob: replace * with any directory name
      const parts = pattern.split('*');
      const parentDir = parts[0] ? path.join(projectPath, parts[0]) : projectPath;
      const suffix = parts.slice(1).join('*') || '';
      if (fs.existsSync(parentDir)) {
        try {
          const entries = fs.readdirSync(parentDir, { withFileTypes: true });
          for (const entry of entries) {
            if (entry.isDirectory()) {
              const fullPath = path.join(parentDir, entry.name, suffix);
              if (fs.existsSync(fullPath)) {
                dirs.push(fullPath);
              }
            }
          }
        } catch {
          // skip unresolvable patterns
        }
      }
    } else {
      // Direct path
      const fullPath = path.join(projectPath, pattern);
      if (fs.existsSync(fullPath)) {
        dirs.push(fullPath);
      }
    }
  }
  return [...new Set(dirs)];
}

/**
 * Parse package-lock.json (lockfileVersion 2+) to extract direct
 * dependencies from the root and any workspace entries.
 */
function extractDepsFromLockfile(lockfilePath: string): PackageScan[] {
  const lockJson = JSON.parse(fs.readFileSync(lockfilePath, 'utf-8'));
  if (!lockJson.packages) return [];
  if (lockJson.lockfileVersion < 2) return [];

  const packages: PackageScan[] = [];
  const seen = new Set<string>();

  for (const [key, entry] of Object.entries(lockJson.packages)) {
    const pkg = entry as Record<string, unknown>;

    // Skip transitive dependencies (installed in node_modules)
    if (key.startsWith('node_modules/')) continue;

    // Collect dependencies from this workspace/root entry
    const deps = {
      ...(pkg.dependencies as Record<string, string> || {}),
      ...(pkg.devDependencies as Record<string, string> || {}),
    };

    for (const [name, version] of Object.entries(deps)) {
      if (!seen.has(name)) {
        seen.add(name);
        packages.push({
          name,
          new_version: String(version).replace('^', '').replace('~', ''),
          registry: 'npm' as const,
        });
      }
    }
  }

  return packages;
}

/**
 * Recursively find manifest files in subdirectories.
 * Excludes hidden directories (starting with '.') and node_modules.
 * Stops recursing into a branch once the file is found there.
 * Max depth is 5 levels from the starting path.
 */
function findManifestFilesRecursive(
  dirPath: string,
  fileName: string,
  maxDepth: number = 5,
  currentDepth: number = 0
): string[] {
  if (currentDepth > maxDepth) return [];
  if (!fs.existsSync(dirPath)) return [];

  const results: string[] = [];

  try {
    const filePath = path.join(dirPath, fileName);
    if (fs.existsSync(filePath)) {
      results.push(filePath);
      // If found in this directory, don't recurse deeper into this branch
      return results;
    }

    const entries = fs.readdirSync(dirPath, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (entry.name.startsWith('.')) continue; // skip hidden dirs
      if (entry.name === 'node_modules') continue;

      const subDir = path.join(dirPath, entry.name);
      results.push(...findManifestFilesRecursive(subDir, fileName, maxDepth, currentDepth + 1));
    }
  } catch {
    // skip inaccessible directories
  }

  return results;
}

function detectManifests(projectPath: string): ManifestSource[] {
  const sources: ManifestSource[] = [];

  // 1. package.json (npm)
  const packageJsonPath = path.join(projectPath, 'package.json');
  let packageJson: Record<string, unknown> | null = null;

  if (fs.existsSync(packageJsonPath)) {
    try {
      packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
      const deps = { ...((packageJson!).dependencies as Record<string, string> || {}), ...((packageJson!).devDependencies as Record<string, string> || {}) };
      const packages: PackageScan[] = Object.entries(deps).map(([name, version]) => ({
        name,
        new_version: String(version).replace('^', '').replace('~', ''),
        registry: 'npm' as const,
      }));
      sources.push({ type: 'npm', path: packageJsonPath, packages });
    } catch (e) {
      console.error(`⚠️  Error reading package.json: ${(e as Error).message}`);
    }
  }

  // 1b. Resolve workspaces (monorepos like "workspaces": ["frontend", "backend"])
  const rootPkg = sources.find(s => s.type === 'npm' && s.path === packageJsonPath);

  const wsField = packageJson?.workspaces;
  if (wsField) {
    const wsPatterns = Array.isArray(wsField)
      ? wsField as string[]
      : ((wsField as { packages?: string[] }).packages || []);

    if (wsPatterns.length > 0) {
      const wsDirs = resolveWorkspacePatterns(projectPath, wsPatterns);
      const wsPackages: PackageScan[] = [];
      const wsSeen = new Set<string>();

      for (const wsDir of wsDirs) {
        const wsPkgPath = path.join(wsDir, 'package.json');
        if (!fs.existsSync(wsPkgPath)) continue;
        try {
          const wsPkg = JSON.parse(fs.readFileSync(wsPkgPath, 'utf-8'));
          const wsDeps = {
            ...(wsPkg.dependencies as Record<string, string> || {}),
            ...(wsPkg.devDependencies as Record<string, string> || {}),
          };
          for (const [name, version] of Object.entries(wsDeps)) {
            if (!wsSeen.has(name)) {
              wsSeen.add(name);
              wsPackages.push({
                name,
                new_version: String(version).replace('^', '').replace('~', ''),
                registry: 'npm' as const,
              });
            }
          }
        } catch {
          // skip unreadable workspace packages
        }
      }

      // Merge workspace packages into existing root source or create new one
      if (rootPkg) {
        rootPkg.packages = [...rootPkg.packages, ...wsPackages];
      } else if (wsPackages.length > 0) {
        sources.push({ type: 'npm', path: projectPath, packages: wsPackages });
      }
    }
  }

  // Count root deps AFTER workspace resolution
  const rootDepsCount = rootPkg?.packages.length ?? 0;

  // 1c. package-lock.json — recursively find as fallback when no deps from package.json
  if (rootDepsCount === 0) {
    const lockPaths = findManifestFilesRecursive(projectPath, 'package-lock.json');
    for (const lockPath of lockPaths) {
      try {
        const lockPackages = extractDepsFromLockfile(lockPath);
        if (lockPackages.length > 0) {
          if (rootPkg) {
            rootPkg.packages = [...rootPkg.packages, ...lockPackages];
          } else {
            sources.push({ type: 'npm', path: lockPath, packages: lockPackages });
          }
        }
      } catch {
        // skip unreadable lockfiles
      }
    }
  }

  // 2. yarn.lock — recursively find all instances
  const yarnLockPaths = findManifestFilesRecursive(projectPath, 'yarn.lock');
  for (const ylPath of yarnLockPaths) {
    try {
      const content = fs.readFileSync(ylPath, 'utf-8');
      const packages = parseYarnLock(content);
      if (packages.length > 0) {
        sources.push({ type: 'yarn', path: ylPath, packages });
      }
    } catch (e) {
      console.error(`⚠️  Error reading ${ylPath}: ${(e as Error).message}`);
    }
  }

  // 3. requirements.txt — recursively find all instances
  const requirementsPaths = findManifestFilesRecursive(projectPath, 'requirements.txt');
  for (const reqPath of requirementsPaths) {
    try {
      const content = fs.readFileSync(reqPath, 'utf-8');
      const packages = parseRequirementsTxt(content);
      if (packages.length > 0) {
        sources.push({ type: 'pypi', path: reqPath, packages });
      }
    } catch (e) {
      console.error(`⚠️  Error reading ${reqPath}: ${(e as Error).message}`);
    }
  }

  return sources;
}

interface ScanResultSummary {
  package_name: string;
  verdict: Verdict;
  confidence_score: number;
  signals: { message: string; check_type: string }[];
  ai_reasoning?: string;
  registry?: string;
}

function printResults(
  results: ScanResultSummary[],
  overallVerdict: Verdict,
  overallConfidence: number,
  summary: string
): void {
  const blocked = results.filter(r => r.verdict === 'BLOCK');
  const warned = results.filter(r => r.verdict === 'WARN');
  const passed = results.filter(r => r.verdict === 'PASS');

  console.log('Summary:');
  console.log(`  ✅ PASS: ${passed.length} packages`);
  console.log(`  ⚠️  WARN: ${warned.length} packages`);
  console.log(`  🚫 BLOCK: ${blocked.length} packages`);
  console.log('');

  // Verdict banner
  if (overallVerdict === 'BLOCK') {
    console.log(`Verdict: 🚫 BLOCKED - Cannot proceed safely (${overallConfidence}% confidence)`);
  } else if (overallVerdict === 'WARN') {
    console.log(`Verdict: ⚠️  WARN - Review recommended (${overallConfidence}% confidence)`);
  } else {
    console.log(`Verdict: ✅ PASS - Safe to proceed (${overallConfidence}% confidence)`);
  }
  console.log('');

  // Details
  console.log('Details:');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  function ecosystemTag(pkg: ScanResultSummary): string {
    return pkg.registry === 'pypi' ? ' [pypi]' : ' [npm]';
  }

  if (passed.length > 0) {
    console.log(`✅ PASS (${passed.length} packages):`);
    for (const pkg of passed.slice(0, 10)) {
      console.log(`  ✓ ${pkg.package_name}${ecosystemTag(pkg)} (${pkg.confidence_score}% confidence)`);
    }
    if (passed.length > 10) {
      console.log(`  ... and ${passed.length - 10} more`);
    }
    console.log('');
  }

  if (warned.length > 0) {
    console.log(`⚠️  WARN (${warned.length} packages):`);
    for (const pkg of warned) {
      console.log(`  ⚠️  ${pkg.package_name}${ecosystemTag(pkg)} (${pkg.confidence_score}% confidence)`);
      for (const signal of pkg.signals.filter(s => s.check_type !== 'ai_analysis')) {
        console.log(`     • ${signal.message}`);
      }
      console.log('');
    }
  }

  if (blocked.length > 0) {
    console.log(`🚫 BLOCK (${blocked.length} packages):`);
    for (const pkg of blocked) {
      console.log(`  🚫 ${pkg.package_name}${ecosystemTag(pkg)} (BLOCK - ${pkg.confidence_score}% confidence)`);
      for (const signal of pkg.signals) {
        console.log(`     • ${signal.message}`);
      }
      if (pkg.ai_reasoning) {
        console.log(`     AI: ${pkg.ai_reasoning}`);
      }
      console.log('');
    }
  }

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  // Next steps
  console.log('Next steps:');
  if (blocked.length > 0) {
    console.log(`  1. ❌ Remove blocked packages from your dependency files`);
  }
  if (warned.length > 0) {
    console.log(`  ${blocked.length > 0 ? '2' : '1'}. ⚠️  Review warned packages and update if needed`);
  }
  const stepNum = (blocked.length > 0 ? 1 : 0) + (warned.length > 0 ? 1 : 0) + 1;
  console.log(`  ${stepNum}. ✅ If all clear, proceed with your package manager install`);
  console.log('');

  // Exit with appropriate code
  if (overallVerdict === 'BLOCK') {
    process.exit(1);
  }
}

// Allow running as a module
export { runCheckAll };

import { PackageScan, CheckResult, ScanResult, Verdict } from './types';
import { checkScriptDiff } from './checks/script-diff';
import { checkCodeAnalysis } from './checks/code-analysis';
import { checkAuthorReputation } from './checks/author-reputation';
import { checkAiAnalysis } from './checks/ai-analysis';

export * from './types';

/**
 * Scanner Engine: Orchestrates all 4 security checks for a given package.
 * Runs checks in parallel where possible, then aggregates results.
 */
export async function scanPackage(
  pkg: PackageScan,
  geminiApiKey?: string
): Promise<ScanResult> {
  // Run the first 3 checks in parallel
  const [scriptDiffResult, codeAnalysisResult, authorRepResult] = await Promise.all([
    checkScriptDiff(pkg),
    checkCodeAnalysis(pkg),
    checkAuthorReputation(pkg),
  ]);

  const checks: CheckResult[] = [
    scriptDiffResult,
    codeAnalysisResult,
    authorRepResult,
  ];

  // Run AI analysis with all previous check results
  const aiResult = await checkAiAnalysis(pkg.name, checks, geminiApiKey || '');

  const allChecks = [...checks, aiResult];

  // Determine verdict
  const verdict = determineVerdict(
    pkg.name,
    allChecks,
    aiResult.verdict,
    aiResult.confidence_score
  );

  // Calculate overall confidence score
  const confidenceScore = aiResult.confidence_score ?? calculateConfidence(allChecks);

  // Generate AI reasoning if available
  const aiReasoning = aiResult.details &&
    typeof aiResult.details === 'object' &&
    'reasoning' in aiResult.details
    ? String(aiResult.details.reasoning)
    : undefined;

  return {
    package_name: pkg.name,
    old_version: pkg.old_version,
    new_version: pkg.new_version,
    verdict,
    confidence_score: confidenceScore,
    signals: allChecks,
    ai_reasoning: aiReasoning,
    registry: pkg.registry,
  };
}

function determineVerdict(
  packageName: string,
  checks: CheckResult[],
  aiVerdict?: Verdict,
  aiConfidence?: number
): Verdict {
  // If AI analysis was performed and returned a verdict, use it
  if (aiVerdict && aiConfidence !== undefined) {
    // Override: if AI says PASS but there are critical non-AI signals, still WARN
    if (aiVerdict === 'PASS') {
      const hasCritical = checks.some(
        c => c.severity === 'critical' && c.check_type !== 'ai_analysis'
      );
      if (hasCritical) return 'WARN';
    }
    return aiVerdict;
  }

  // Fallback: determine verdict from individual checks
  const criticals = checks.filter(c => c.severity === 'critical');
  const warnings = checks.filter(c => c.severity === 'warning');

  if (criticals.length > 0) return 'BLOCK';
  if (warnings.length === 0) return 'PASS';

  // Smart downgrade: if the ONLY warnings come from code_analysis and
  // the package has good author reputation, treat as PASS.
  // This prevents well-known packages (express, react, etc.) from being
  // flagged for common-but-suspicious patterns like child_process, net, etc.
  const codeAnalysisWarnings = checks.filter(
    c => c.check_type === 'code_analysis' && c.severity === 'warning'
  );
  const otherWarnings = warnings.filter(
    c => c.check_type !== 'code_analysis'
  );
  const authorRepIsGood = checks.some(
    c => c.check_type === 'author_reputation' && c.severity === 'info'
  );

  if (codeAnalysisWarnings.length > 0 && otherWarnings.length === 0 && authorRepIsGood) {
    // eslint-disable-next-line no-console
    console.log(`   ℹ️  ${packageName}: Warnings from code analysis only — author reputation is good, downgrading to PASS`);
    return 'PASS';
  }

  return 'WARN';
}

function calculateConfidence(checks: CheckResult[]): number {
  const severities = checks.map(c => c.severity);
  const criticalCount = severities.filter(s => s === 'critical').length;
  const warningCount = severities.filter(s => s === 'warning').length;

  if (criticalCount > 0) {
    return Math.max(0, 30 - criticalCount * 15);
  }
  if (warningCount > 0) {
    return Math.max(40, 80 - warningCount * 10);
  }
  return 95; // All clear
}

/**
 * Scan multiple packages and return results for all of them.
 */
export async function scanPackages(
  packages: PackageScan[],
  geminiApiKey?: string
): Promise<{
  results: ScanResult[];
  overallVerdict: Verdict;
  overallConfidence: number;
  summary: string;
}> {
  const results = await Promise.all(
    packages.map(pkg => scanPackage(pkg, geminiApiKey))
  );

  // Determine overall verdict
  const blocked = results.filter(r => r.verdict === 'BLOCK');
  const warned = results.filter(r => r.verdict === 'WARN');
  const passed = results.filter(r => r.verdict === 'PASS');

  let overallVerdict: Verdict;
  if (blocked.length > 0) {
    overallVerdict = 'BLOCK';
  } else if (warned.length > 0) {
    overallVerdict = 'WARN';
  } else {
    overallVerdict = 'PASS';
  }

  // Average confidence for overall
  const avgConfidence = Math.round(
    results.reduce((sum, r) => sum + r.confidence_score, 0) / results.length
  );

  // Generate summary
  const parts: string[] = [];
  if (passed.length > 0) parts.push(`${passed.length} safe`);
  if (warned.length > 0) parts.push(`${warned.length} need review`);
  if (blocked.length > 0) parts.push(`${blocked.length} blocked`);
  const summary = parts.length > 0
    ? `${results.length} packages scanned: ${parts.join(', ')}`
    : 'No packages scanned';

  return {
    results,
    overallVerdict,
    overallConfidence: avgConfidence,
    summary,
  };
}

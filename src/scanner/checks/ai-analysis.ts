import { CheckResult, Verdict } from '../types';

/**
 * Check 4: AI Analysis (Google Gemini)
 * Analyzes all previous check results and generates a final verdict
 * with human-readable reasoning and confidence score.
 */
export async function checkAiAnalysis(
  packageName: string,
  previousChecks: CheckResult[],
  apiKey: string
): Promise<CheckResult & { verdict?: Verdict; confidence_score?: number }> {
  if (!apiKey) {
    return {
      check_type: 'ai_analysis',
      severity: 'info',
      message: `${packageName}: AI analysis skipped (no API key configured)`,
      verdict: undefined,
      confidence_score: undefined,
    };
  }

  try {
    const { GoogleGenerativeAI } = await import('@google/generative-ai');
    const genAI = new GoogleGenerativeAI(apiKey);
    const model = genAI.getGenerativeModel({ model: 'gemini-2.0-flash' });

    const checksJson = JSON.stringify(previousChecks, null, 2);

    const prompt = `You are a supply chain security expert analyzing npm package "${packageName}" for malicious activity.

Below are the results from 3 automated security checks:

${checksJson}

Analyze these results and provide:
1. A final verdict (PASS, WARN, or BLOCK)
2. A confidence score (0-100, where 0 = definitely malicious, 100 = definitely safe)
3. A concise reasoning paragraph explaining your verdict in plain English

Consider:
- If critical severity checks exist, the package is likely BLOCK
- Multiple warnings may warrant a WARN verdict
- All info-level checks with no warnings = PASS
- Context matters: major version bumps may have expected changes
- Widely used/established packages are less likely to be malicious

Respond with a JSON object only:
{
  "verdict": "PASS|WARN|BLOCK",
  "confidence_score": number,
  "reasoning": "string"
}`;

    const result = await model.generateContent(prompt);
    const response = result.response;
    const text = response.text();

    // Parse the JSON response
    let parsed: { verdict?: string; confidence_score?: number; reasoning?: string } = {};
    try {
      // Extract JSON from the response (handle markdown code blocks)
      const jsonMatch = text.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        parsed = JSON.parse(jsonMatch[0]);
      }
    } catch {
      // Fallback: try parsing the whole text
      try {
        parsed = JSON.parse(text);
      } catch {
        // If parsing fails, use a default
        parsed = { verdict: 'PASS', confidence_score: 50, reasoning: 'Could not parse AI response' };
      }
    }

    const verdict = (parsed.verdict as Verdict) || 'PASS';
    const confidence = typeof parsed.confidence_score === 'number' ? parsed.confidence_score : 50;
    const reasoning = parsed.reasoning || 'No reasoning provided';

    // Determine severity based on verdict
    let severity: 'info' | 'warning' | 'critical';
    if (verdict === 'BLOCK') {
      severity = 'critical';
    } else if (verdict === 'WARN') {
      severity = 'warning';
    } else {
      severity = 'info';
    }

    return {
      check_type: 'ai_analysis',
      severity,
      message: `${packageName}: ${verdict} (${confidence}% confidence)`,
      details: {
        reasoning,
        verdict,
        confidence_score: confidence,
      },
      verdict,
      confidence_score: confidence,
    };
  } catch (error) {
    return {
      check_type: 'ai_analysis',
      severity: 'info',
      message: `${packageName}: AI analysis failed (${(error as Error).message})`,
      details: { error: String(error) },
      verdict: undefined,
      confidence_score: undefined,
    };
  }
}

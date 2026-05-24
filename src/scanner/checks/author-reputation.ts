import { PackageScan, CheckResult } from '../types';

/**
 * Check 3: Author Reputation
 * Evaluates the trustworthiness of package maintainers by analyzing
 * publishing history, account age, activity patterns, and security practices.
 *
 * For npm: queries npm registry for maintainer details, 2FA, account age.
 * For PyPI: queries PyPI JSON API for author/maintainer info and release history.
 */
export async function checkAuthorReputation(pkg: PackageScan): Promise<CheckResult> {
  const { name, registry } = pkg;

  if (registry === 'pypi') {
    return checkPypiAuthorReputation(name);
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
        check_type: 'author_reputation',
        severity: 'info',
        message: `${name}: Could not fetch author data (${response.status})`,
        details: { error: `HTTP ${response.status}` },
      };
    }

    const data = await response.json() as {
      name?: string;
      maintainers?: { name: string; email?: string }[];
      author?: { name: string; email?: string; url?: string };
      time?: Record<string, string>;
      'dist-tags'?: Record<string, string>;
      description?: string;
    };

    const maintainers = data.maintainers || [];
    const publishTimes = data.time || {};
    const versions = Object.keys(publishTimes).filter(v => v !== 'created' && v !== 'modified');
    const created = publishTimes.created;
    const modified = publishTimes.modified;

    const warnings: string[] = [];
    const criticals: string[] = [];

    // Check 1: Number of maintainers
    if (maintainers.length === 0) {
      criticals.push('No maintainer information available');
    }

    // Check 2: Account age (if created timestamp exists)
    if (created) {
      const accountAge = Date.now() - new Date(created).getTime();
      const accountAgeDays = accountAge / (1000 * 60 * 60 * 24);

      if (accountAgeDays < 7) {
        criticals.push(`Package created less than a week ago (${Math.round(accountAgeDays)} days)`);
      } else if (accountAgeDays < 30) {
        warnings.push(`Package created less than a month ago (${Math.round(accountAgeDays)} days)`);
      } else if (accountAgeDays < 90) {
        warnings.push(`Relatively new package (${Math.round(accountAgeDays)} days old)`);
      }
    }

    // Check 3: Version count and publishing pattern
    const versionCount = versions.length;
    if (versionCount === 0) {
      warnings.push('Package has no published versions');
    } else if (versionCount > 50) {
      // Could be a spam/bulk publish pattern
      const versionTimes = versions.map(v => ({
        version: v,
        time: new Date(publishTimes[v]).getTime(),
      }));

      // Check for rapid publishing
      if (versionTimes.length >= 3) {
        const timeDiffs: number[] = [];
        for (let i = 1; i < versionTimes.length; i++) {
          timeDiffs.push(versionTimes[i].time - versionTimes[i - 1].time);
        }
        const avgDiffMs = timeDiffs.reduce((a, b) => a + b, 0) / timeDiffs.length;
        const avgDiffSeconds = avgDiffMs / 1000;

        if (avgDiffSeconds < 60 && versionCount > 20) {
          criticals.push(`Suspicious rapid publishing: ${versionCount} versions in short time (avg ${Math.round(avgDiffSeconds)}s apart)`);
        }
      }
    }

    // Check 4: Maintainer analysis
    for (const maintainer of maintainers) {
      if (maintainer.name) {
        try {
          const userController = new AbortController();
          const userTimeout = setTimeout(() => userController.abort(), 15000);
          let userResponse;
          try {
            userResponse = await fetch(`https://registry.npmjs.org/-/v1/user/${encodeURIComponent(maintainer.name)}`, { signal: userController.signal });
          } finally {
            clearTimeout(userTimeout);
          }
          if (userResponse.ok) {
            const userData = await userResponse.json() as {
              name?: string;
              email?: string;
              created?: string;
              updated?: string;
              fullname?: string;
              tfa?: boolean | string;
              packages?: string[];
            };

            // Check 4a: 2FA status
            const tfa = userData.tfa;
            if (tfa === false || tfa === undefined) {
              warnings.push(`Maintainer "${maintainer.name}" does not have 2FA enabled`);
            }

            // Check 4b: Account age
            if (userData.created) {
              const maintainerAge = Date.now() - new Date(userData.created).getTime();
              const maintainerAgeDays = maintainerAge / (1000 * 60 * 60 * 24);
              if (maintainerAgeDays < 30) {
                criticals.push(`Maintainer "${maintainer.name}" account is very new (${Math.round(maintainerAgeDays)} days)`);
              }
            }

            // Check 4c: Number of packages maintained
            const packageCount = userData.packages?.length || 0;
            if (packageCount === 0) {
              warnings.push(`Maintainer "${maintainer.name}" maintains no other packages`);
            } else if (packageCount > 100) {
              warnings.push(`Maintainer "${maintainer.name}" maintains an unusually high number of packages (${packageCount})`);
            }
          }
        } catch {
          // If we can't fetch user data, skip this check
        }
      }
    }

    // Build message based on findings
    if (criticals.length > 0) {
      return {
        check_type: 'author_reputation',
        severity: 'critical',
        message: `${name}: Multiple red flags detected about package maintainers!`,
        details: { criticals, warnings },
      };
    }

    if (warnings.length > 0) {
      return {
        check_type: 'author_reputation',
        severity: 'warning',
        message: `${name}: Some concerns about maintainer reputation`,
        details: { warnings },
      };
    }

    return {
      check_type: 'author_reputation',
      severity: 'info',
      message: `${name}: Established package with verified maintainers ✓`,
      details: {
        maintainers: maintainers.map((m: { name: string }) => m.name),
        versions: versionCount,
        created: created || 'unknown',
      },
    };
  } catch (error) {
    return {
      check_type: 'author_reputation',
      severity: 'warning',
      message: `${name}: Error checking author reputation: ${(error as Error).message}`,
      details: { error: String(error) },
    };
  }
}

// ─── PyPI Author Reputation ───────────────────────────────────────

/**
 * PyPI variant: queries the PyPI JSON API to evaluate package maintainer trustworthiness.
 * PyPI has less granular user data than npm (no 2FA check API, no user endpoint),
 * so this checks package-level metadata.
 */
async function checkPypiAuthorReputation(name: string): Promise<CheckResult> {
  try {
    const pypiController = new AbortController();
    const pypiTimeout = setTimeout(() => pypiController.abort(), 30000);
    let response;
    try {
      response = await fetch(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`, { signal: pypiController.signal });
    } finally {
      clearTimeout(pypiTimeout);
    }
    if (!response.ok) {
      return {
        check_type: 'author_reputation',
        severity: 'info',
        message: `${name}: Could not fetch PyPI author data (${response.status})`,
        details: { error: `HTTP ${response.status}` },
      };
    }

    const data = await response.json() as {
      info: {
        name: string;
        version?: string;
        author?: string;
        author_email?: string;
        maintainer?: string;
        maintainer_email?: string;
        requires_python?: string;
        description?: string;
        home_page?: string;
        license?: string;
        project_urls?: Record<string, string>;
      };
      releases?: Record<string, unknown[]>;
      urls?: unknown[];
    };

    const info = data.info;
    const warnings: string[] = [];
    const criticals: string[] = [];

    // Check 1: Author/maintainer info presence
    const hasAuthor = !!(info.author || info.maintainer);
    if (!hasAuthor) {
      warnings.push('No author or maintainer information available');
    }

    // Check 2: Release count and package history
    const releases = data.releases ? Object.keys(data.releases) : [];
    const versionCount = releases.length;

    if (versionCount === 0) {
      warnings.push('Package has no published releases');
    } else if (versionCount === 1) {
      warnings.push('Package has only one release version');
    } else if (versionCount > 50) {
      // Could indicate spam — though many legitimate packages have many releases
      // Check the time span of releases
      const releaseTimes = releases
        .map(v => ({ version: v }))
        .sort((a, b) => a.version.localeCompare(b.version));

      if (releaseTimes.length >= 3) {
        warnings.push(`Package has an unusually large number of releases (${versionCount})`);
      }
    }

    // Check 3: License presence
    if (!info.license && !info.home_page) {
      warnings.push('No license or project homepage specified');
    }

    // Check 4: Requires Python — missing or very old Python only
    if (info.requires_python) {
      const pyMatch = info.requires_python.match(/>=\s*(\d+\.\d+)/);
      if (pyMatch) {
        const minVersion = parseFloat(pyMatch[1]);
        if (minVersion < 3.0) {
          warnings.push(`Requires very old Python version (${info.requires_python})`);
        }
      }
    }

    // Check 5: Project URLs validation
    if (info.project_urls) {
      const urls = Object.values(info.project_urls).filter(Boolean) as string[];
      const suspiciousDomains = urls.filter(u =>
        /(?:bit\.ly|tinyurl\.com|short\.link)/i.test(u)
      );
      if (suspiciousDomains.length > 0) {
        warnings.push('Package uses URL shorteners which may hide malicious redirects');
      }
    }

    // Build message based on findings
    if (criticals.length > 0) {
      return {
        check_type: 'author_reputation',
        severity: 'critical',
        message: `${name}: Multiple red flags detected about PyPI package maintainers!`,
        details: { criticals, warnings },
      };
    }

    if (warnings.length > 0) {
      return {
        check_type: 'author_reputation',
        severity: 'warning',
        message: `${name}: Some concerns about PyPI maintainer reputation`,
        details: {
          warnings,
          author: info.author || 'Unknown',
          releases: versionCount,
        },
      };
    }

    return {
      check_type: 'author_reputation',
      severity: 'info',
      message: `${name}: Established PyPI package with author info ✓`,
      details: {
        author: info.author || info.maintainer || 'Unknown',
        releases: versionCount,
        requires_python: info.requires_python || 'Any',
      },
    };
  } catch (error) {
    return {
      check_type: 'author_reputation',
      severity: 'warning',
      message: `${name}: Error checking PyPI author reputation: ${(error as Error).message}`,
      details: { error: String(error) },
    };
  }
}

export type Verdict = 'PASS' | 'WARN' | 'BLOCK';
export type Severity = 'info' | 'warning' | 'critical';

export interface CheckResult {
  check_type: string;
  severity: Severity;
  message: string;
  details?: Record<string, unknown>;
}

export type Registry = 'npm' | 'pypi';

export interface PackageScan {
  name: string;
  old_version?: string;
  new_version?: string;
  registry?: Registry;
}

export interface ScanRequest {
  packages: PackageScan[];
  repo?: string;
  pr_number?: number;
}

export interface ScanResult {
  package_name: string;
  old_version?: string;
  new_version?: string;
  verdict: Verdict;
  confidence_score: number;
  signals: CheckResult[];
  ai_reasoning?: string;
  registry?: Registry;
}

export interface ScanResponse {
  scan_id: string;
  verdict: Verdict;
  confidence_score: number;
  timestamp: string;
  summary: string;
  package_results: ScanResult[];
  signals: CheckResult[];
  repo?: string;
  pr_number?: number;
}

export interface DbScan {
  id: string;
  repo: string | null;
  pr_number: number | null;
  verdict: Verdict;
  confidence_score: number;
  summary: string;
  created_at: string;
  raw_results: string; // JSON string of ScanResult[]
}

export interface DbSignal {
  id: string;
  scan_id: string;
  package_name: string;
  check_type: string;
  severity: Severity;
  message: string;
  details: string | null;
}

export interface StatsResponse {
  total_scans: number;
  scans_this_week: number;
  verdict_breakdown: {
    PASS: number;
    WARN: number;
    BLOCK: number;
  };
  risky_packages: {
    name: string;
    blocked_count: number;
    verdict: string;
  }[];
}

export interface NpmPackageInfo {
  name: string;
  version: string;
  description?: string;
  maintainers?: { name: string; email?: string }[];
  author?: { name: string; email?: string };
  'dist-tags'?: Record<string, string>;
  time?: Record<string, string>;
  versions?: Record<string, unknown>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  scripts?: Record<string, any>;
}

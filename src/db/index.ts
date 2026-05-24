import initSqlJs, { Database as SqlJsDatabase } from 'sql.js';
import fs from 'fs';
import path from 'path';
import { DbScan, DbSignal, ScanResponse, ScanResult, Verdict, StatsResponse } from '../scanner/types';

let db: SqlJsDatabase | null = null;
let dbPath: string = '';

export async function getDb(): Promise<SqlJsDatabase> {
  if (db) return db;

  const SQL = await initSqlJs();
  dbPath = process.env.DB_PATH || './data/sentinel.db';
  const dbDir = path.dirname(dbPath);

  if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
  }

  // Try to load existing database file
  if (fs.existsSync(dbPath)) {
    const buffer = fs.readFileSync(dbPath);
    db = new SQL.Database(buffer);
  } else {
    db = new SQL.Database();
  }

  db.run('PRAGMA foreign_keys = ON');
  return db;
}

function saveDb(): void {
  if (!db) return;
  const data = db.export();
  const buffer = Buffer.from(data);
  fs.writeFileSync(dbPath, buffer);
}

export async function initializeDatabase(): Promise<void> {
  const database = await getDb();

  database.run(`
    CREATE TABLE IF NOT EXISTS scans (
      id TEXT PRIMARY KEY,
      repo TEXT,
      pr_number INTEGER,
      verdict TEXT NOT NULL,
      confidence_score INTEGER NOT NULL,
      summary TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      raw_results TEXT
    )
  `);

  database.run(`
    CREATE TABLE IF NOT EXISTS signals (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL,
      package_name TEXT NOT NULL,
      check_type TEXT NOT NULL,
      severity TEXT NOT NULL,
      message TEXT NOT NULL,
      details TEXT,
      FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
    )
  `);

  database.run('CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC)');
  database.run('CREATE INDEX IF NOT EXISTS idx_scans_verdict ON scans(verdict)');
  database.run('CREATE INDEX IF NOT EXISTS idx_scans_repo ON scans(repo)');
  database.run('CREATE INDEX IF NOT EXISTS idx_signals_scan_id ON signals(scan_id)');

  saveDb();
  console.log('✅ Database tables created');
}

export function closeDb(): void {
  if (db) {
    saveDb();
    db.close();
    db = null;
  }
}

export function saveScan(scanId: string, response: ScanResponse): void {
  if (!db) throw new Error('Database not initialized');

  const scanSql = `
    INSERT INTO scans (id, repo, pr_number, verdict, confidence_score, summary, created_at, raw_results)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `;

  const signalSql = `
    INSERT INTO signals (id, scan_id, package_name, check_type, severity, message, details)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `;

  db.run('BEGIN TRANSACTION');

  try {
    db.run(scanSql, [
      scanId,
      response.repo || null,
      response.pr_number || null,
      response.verdict,
      response.confidence_score,
      response.summary,
      response.timestamp,
      JSON.stringify(response.package_results),
    ]);

    for (const pkgResult of response.package_results) {
      for (const signal of pkgResult.signals) {
        db.run(signalSql, [
          `${scanId}-${pkgResult.package_name}-${signal.check_type}`,
          scanId,
          pkgResult.package_name,
          signal.check_type,
          signal.severity,
          signal.message,
          signal.details ? JSON.stringify(signal.details) : null,
        ]);
      }
    }

    db.run('COMMIT');
    saveDb();
  } catch (error) {
    db.run('ROLLBACK');
    throw error;
  }
}

export function getScans(limit = 50): DbScan[] {
  if (!db) throw new Error('Database not initialized');
  const stmt = db.prepare(`SELECT * FROM scans ORDER BY created_at DESC LIMIT ${limit}`);
  const rows: DbScan[] = [];
  while (stmt.step()) {
    rows.push(stmt.getAsObject() as unknown as DbScan);
  }
  stmt.free();
  return rows;
}

export function getScansFiltered(params: {
  repo?: string;
  verdict?: string;
  days?: number;
  limit?: number;
}): DbScan[] {
  if (!db) throw new Error('Database not initialized');

  const conditions: string[] = [];
  const values: (string | number)[] = [];

  if (params.repo) {
    conditions.push('repo = ?');
    values.push(params.repo);
  }
  if (params.verdict) {
    conditions.push('verdict = ?');
    values.push(params.verdict);
  }
  if (params.days) {
    conditions.push(`created_at >= datetime('now', ? || ' days')`);
    values.push(-params.days);
  }

  const where = conditions.length > 0 ? 'WHERE ' + conditions.join(' AND ') : '';
  const limit = params.limit || 50;

  const sql = `SELECT * FROM scans ${where} ORDER BY created_at DESC LIMIT ${limit}`;
  const stmt = db.prepare(sql);
  stmt.bind(values);
  const rows: DbScan[] = [];
  while (stmt.step()) {
    const row = stmt.getAsObject() as Record<string, unknown>;
    rows.push(row as unknown as DbScan);
  }
  stmt.free();

  return rows;
}

export function getScanById(scanId: string): { scan: DbScan | null; signals: DbSignal[] } {
  if (!db) throw new Error('Database not initialized');

  const scanStmt = db.prepare('SELECT * FROM scans WHERE id = ?');
  scanStmt.bind([scanId]);
  let scan: DbScan | null = null;
  if (scanStmt.step()) {
    scan = scanStmt.getAsObject() as unknown as DbScan;
  }
  scanStmt.free();

  if (!scan) return { scan: null, signals: [] };

  const signalStmt = db.prepare('SELECT * FROM signals WHERE scan_id = ?');
  signalStmt.bind([scanId]);
  const signals: DbSignal[] = [];
  while (signalStmt.step()) {
    signals.push(signalStmt.getAsObject() as unknown as DbSignal);
  }
  signalStmt.free();

  return { scan, signals };
}

export function getStats(): StatsResponse {
  if (!db) throw new Error('Database not initialized');

  const totalScans = (db.exec('SELECT COUNT(*) as count FROM scans')[0]?.values[0]?.[0] as number) || 0;

  const scansThisWeek = (db.exec(`
    SELECT COUNT(*) as count FROM scans
    WHERE created_at >= datetime('now', '-7 days')
  `)[0]?.values[0]?.[0] as number) || 0;

  const passCount = (db.exec("SELECT COUNT(*) as count FROM scans WHERE verdict = 'PASS'")[0]?.values[0]?.[0] as number) || 0;
  const warnCount = (db.exec("SELECT COUNT(*) as count FROM scans WHERE verdict = 'WARN'")[0]?.values[0]?.[0] as number) || 0;
  const blockCount = (db.exec("SELECT COUNT(*) as count FROM scans WHERE verdict = 'BLOCK'")[0]?.values[0]?.[0] as number) || 0;

  const riskyRows = db.exec(`
    SELECT package_name as name, COUNT(*) as blocked_count, 'BLOCK' as verdict
    FROM signals
    WHERE severity = 'critical'
    GROUP BY package_name
    ORDER BY blocked_count DESC
    LIMIT 10
  `);

  const riskyPackages: { name: string; blocked_count: number; verdict: string }[] = [];
  if (riskyRows.length > 0) {
    for (const row of riskyRows[0].values) {
      riskyPackages.push({
        name: row[0] as string,
        blocked_count: row[1] as number,
        verdict: row[2] as string,
      });
    }
  }

  return {
    total_scans: totalScans as number,
    scans_this_week: scansThisWeek as number,
    verdict_breakdown: {
      PASS: passCount as number,
      WARN: warnCount as number,
      BLOCK: blockCount as number,
    },
    risky_packages: riskyPackages,
  };
}

// Graceful shutdown
process.on('exit', () => closeDb());
process.on('SIGINT', () => { closeDb(); process.exit(0); });
process.on('SIGTERM', () => { closeDb(); process.exit(0); });

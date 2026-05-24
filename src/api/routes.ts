import { Router, Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { scanPackages } from '../scanner/index';
import { ScanRequest } from '../scanner/types';
import { saveScan, getScansFiltered, getScanById, getStats } from '../db/index';
import { authMiddleware } from './auth';

const router = Router();

// Apply auth to all routes
router.use(authMiddleware);

/**
 * POST /api/scans
 * Scan packages and return verdict
 */
router.post('/scans', async (req: Request, res: Response) => {
  try {
    const body = req.body as ScanRequest;

    if (!body.packages || !Array.isArray(body.packages) || body.packages.length === 0) {
      res.status(400).json({ error: 'Bad Request', status: 400, message: 'packages array is required' });
      return;
    }

    if (body.packages.length > 50) {
      res.status(400).json({
        error: 'Bad Request',
        status: 400,
        message: 'Maximum 50 packages per request. Split into batches.',
      });
      return;
    }

    const geminiApiKey = process.env.GEMINI_API_KEY;

    const scanId = uuidv4();
    const timestamp = new Date().toISOString();

    const scanResult = await scanPackages(body.packages, geminiApiKey);

    const response = {
      scan_id: scanId,
      verdict: scanResult.overallVerdict,
      confidence_score: scanResult.overallConfidence,
      timestamp,
      summary: scanResult.summary,
      package_results: scanResult.results,
      signals: scanResult.results.flatMap(r => r.signals),
      repo: body.repo,
      pr_number: body.pr_number,
    };

    // Save to database (async, don't block response)
    try {
      saveScan(scanId, response);
    } catch (dbError) {
      console.error('Failed to save scan to database:', dbError);
    }

    res.json(response);
  } catch (error) {
    console.error('Scan error:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      status: 500,
      message: (error as Error).message,
    });
  }
});

/**
 * GET /api/scans
 * List recent scans with filtering
 */
router.get('/scans', (req: Request, res: Response) => {
  try {
    const repo = typeof req.query.repo === 'string' ? req.query.repo : undefined;
    const verdict = typeof req.query.verdict === 'string' ? req.query.verdict : undefined;
    const days = typeof req.query.days === 'string' ? parseInt(req.query.days, 10) : undefined;
    const limit = typeof req.query.limit === 'string' ? parseInt(req.query.limit, 10) : undefined;

    const scans = getScansFiltered({
      repo,
      verdict,
      days,
      limit: limit || 50,
    });

    const total = scans.length;

    res.json({
      scans: scans.map(s => ({
        id: s.id,
        repo: s.repo,
        pr_number: s.pr_number,
        verdict: s.verdict,
        confidence_score: s.confidence_score,
        created_at: s.created_at,
      })),
      total,
      page: 1,
    });
  } catch (error) {
    console.error('List scans error:', error);
    res.status(500).json({ error: 'Internal Server Error', status: 500, message: (error as Error).message });
  }
});

/**
 * GET /api/scans/:scanId
 * Get detailed scan results
 */
router.get('/scans/:scanId', (req: Request, res: Response) => {
  try {
    const scanId = req.params.scanId as string;
    const result = getScanById(scanId);

    if (!result.scan) {
      res.status(404).json({ error: 'Not Found', status: 404, message: 'Scan not found' });
      return;
    }

    res.json({
      id: result.scan.id,
      repo: result.scan.repo,
      pr_number: result.scan.pr_number,
      verdict: result.scan.verdict,
      confidence_score: result.scan.confidence_score,
      created_at: result.scan.created_at,
      signals: result.signals.map(s => ({
        id: s.id,
        check_type: s.check_type,
        severity: s.severity,
        message: s.message,
        result: s.details ? JSON.parse(s.details) : {},
      })),
    });
  } catch (error) {
    console.error('Get scan error:', error);
    res.status(500).json({ error: 'Internal Server Error', status: 500, message: (error as Error).message });
  }
});

/**
 * GET /api/stats
 * Dashboard statistics
 */
router.get('/stats', (_req: Request, res: Response) => {
  try {
    const stats = getStats();
    res.json(stats);
  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({ error: 'Internal Server Error', status: 500, message: (error as Error).message });
  }
});

export default router;

import { Request, Response, NextFunction } from 'express';

export function authMiddleware(req: Request, res: Response, next: NextFunction): void {
  const apiKey = req.headers['x-api-key'] as string | undefined;
  const validKey = process.env.SENTINEL_API_KEY;

  if (!validKey) {
    // If no API key is configured, allow all requests (development mode)
    next();
    return;
  }

  if (!apiKey) {
    res.status(401).json({ error: 'Unauthorized', status: 401, message: 'Missing X-API-Key header' });
    return;
  }

  if (apiKey !== validKey) {
    res.status(401).json({ error: 'Unauthorized', status: 401, message: 'Invalid API key' });
    return;
  }

  next();
}

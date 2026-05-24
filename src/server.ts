import dotenv from 'dotenv';
import path from 'path';

// Load .env first
dotenv.config({ path: path.resolve(__dirname, '../.env') });

import express from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { initializeDatabase, closeDb } from './db/index';
import apiRoutes from './api/routes';

const app = express();
const PORT = parseInt(process.env.PORT || '5000', 10);

// Middleware
app.use(cors());
app.use(express.json({ limit: '1mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: parseInt(process.env.RATE_LIMIT_RPM || '30', 10),
  message: { error: 'Rate limit exceeded. Retry after 60 seconds.', status: 429 },
});
app.use('/api/', limiter);

// API routes
app.use('/api', apiRoutes);

// Health check
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', version: '1.0.0', timestamp: new Date().toISOString() });
});

// Start server after database initialization
initializeDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`
🛡️  Sentinel API Server
━━━━━━━━━━━━━━━━━━━━━━━
Port:     ${PORT}
Mode:     ${process.env.NODE_ENV || 'development'}
Dashboard: http://localhost:${PORT === 5000 ? 3000 : PORT}
API:      http://localhost:${PORT}/api
Health:   http://localhost:${PORT}/health

Press Ctrl+C to stop
`);
    });
  })
  .catch((error) => {
    console.error('❌ Failed to initialize database:', error);
    process.exit(1);
  });

// Graceful shutdown
function shutdown(): void {
  console.log('\nShutting down gracefully...');
  closeDb();
  process.exit(0);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

export default app;

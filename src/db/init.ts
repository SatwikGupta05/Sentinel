import dotenv from 'dotenv';
import path from 'path';

// Load .env from root
dotenv.config({ path: path.resolve(__dirname, '../../.env') });

import { initializeDatabase, closeDb } from './index';

console.log('🛡️  Sentinel - Database Initialization');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

const dbType = process.env.DB_TYPE || 'sqlite';
console.log(`Database type: ${dbType}`);

if (dbType === 'sqlite') {
  const dbPath = process.env.DB_PATH || './data/sentinel.db';
  console.log(`Database path: ${dbPath}`);
  console.log('Initializing SQLite database...');

  initializeDatabase()
    .then(() => {
      console.log('✅ SQLite database initialized successfully!');
      closeDb();
      console.log('\nDone! Run `npm run dev` to start the server.');
    })
    .catch((error) => {
      console.error('❌ Failed to initialize database:', error);
      process.exit(1);
    });
} else {
  console.log(`Database type "${dbType}" is not supported for direct initialization.`);
  console.log('For Supabase, run the SQL migrations manually in the Supabase SQL Editor.');
}

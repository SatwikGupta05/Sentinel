import crypto from 'crypto';

const key = 'sk_sentinel_' + crypto.randomBytes(24).toString('hex');

console.log('\n🛡️  Sentinel - API Key Generator');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
console.log(`Generated API Key: ${key}\n`);
console.log('Add this to your .env file:');
console.log(`SENTINEL_API_KEY=${key}\n`);
console.log('For GitHub Actions, add as a secret: SENTINEL_API_KEY\n');

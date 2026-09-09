import { connectToDatabase } from '@/lib/db';
import { registerScanProcessor } from '@/lib/queue';
import { processScanJob } from './scanProcessor';

async function startWorker() {
  console.log('🚀 Starting Pliora Standalone Security Worker...');
  await connectToDatabase();
  console.log('✅ Connected to Database.');

  registerScanProcessor(processScanJob);
  console.log('🛡️  Worker is listening for scan jobs...');
}

startWorker().catch((err) => {
  console.error('Fatal worker startup error:', err);
  process.exit(1);
});

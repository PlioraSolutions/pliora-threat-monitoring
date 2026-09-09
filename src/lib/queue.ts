import { Queue, Worker, Job } from 'bullmq';
import IORedis from 'ioredis';
import { env } from './env';

export interface ScanJobData {
  scanId: string;
  organizationId: string;
  assetId: string;
  scanType: 'DOMAIN_VERIFICATION' | 'DISCOVERY' | 'EXPOSURE' | 'FULL_SWEEP';
}

// Memory queue fallback store for development/testing when Redis is not running
const inMemoryJobs: ScanJobData[] = [];
let isMemoryProcessing = false;
let registeredWorkerProcessor: ((data: ScanJobData) => Promise<void>) | null = null;

let redisClient: IORedis | null = null;
let scanQueue: Queue | null = null;

function getRedisConnection(): IORedis | null {
  if (!redisClient && !env.ENABLE_IN_MEMORY_QUEUE_FALLBACK) {
    try {
      redisClient = new IORedis(env.REDIS_URL, {
        maxRetriesPerRequest: null,
        enableReadyCheck: false,
        retryStrategy: () => null, // don't hang indefinitely if offline
      });
      redisClient.on('error', (err) => {
        console.warn('[Queue] Redis connection error, will use memory fallback:', err.message);
      });
    } catch (e) {
      console.warn('[Queue] Failed to initialize Redis client:', e);
      redisClient = null;
    }
  }
  return redisClient;
}

/**
 * Registers the background processor function that executes scan logic.
 */
export function registerScanProcessor(processor: (data: ScanJobData) => Promise<void>) {
  registeredWorkerProcessor = processor;

  // If Redis is active, initialize BullMQ worker
  const connection = getRedisConnection();
  if (connection && !env.ENABLE_IN_MEMORY_QUEUE_FALLBACK) {
    try {
      new Worker(
        'scan-jobs',
        async (job: Job<ScanJobData>) => {
          await processor(job.data);
        },
        { connection, concurrency: env.SCAN_WORKER_CONCURRENCY }
      );
      console.log('[Queue] BullMQ Redis Worker started.');
    } catch (err) {
      console.warn('[Queue] Could not start BullMQ Redis worker:', err);
    }
  }
}

/**
 * Enqueues a scan job to the queue (either BullMQ or resilient in-process queue).
 */
export async function enqueueScanJob(data: ScanJobData): Promise<{ queued: boolean; jobId: string }> {
  const connection = getRedisConnection();

  if (connection && !env.ENABLE_IN_MEMORY_QUEUE_FALLBACK) {
    try {
      if (!scanQueue) {
        scanQueue = new Queue('scan-jobs', { connection });
      }
      const job = await scanQueue.add('execute-scan', data, {
        attempts: 2,
        backoff: { type: 'exponential', delay: 2000 },
        removeOnComplete: true,
      });
      return { queued: true, jobId: job.id || `redis-${Date.now()}` };
    } catch (e) {
      console.warn('[Queue] BullMQ enqueue failed, falling back to memory queue:', e);
    }
  }

  // Resilient memory dispatcher
  const jobId = `mem-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
  inMemoryJobs.push(data);
  triggerMemoryQueueDrain();
  return { queued: true, jobId };
}

function triggerMemoryQueueDrain() {
  if (isMemoryProcessing) return;
  isMemoryProcessing = true;

  setImmediate(async () => {
    while (inMemoryJobs.length > 0) {
      const nextJob = inMemoryJobs.shift();
      if (nextJob && registeredWorkerProcessor) {
        try {
          await registeredWorkerProcessor(nextJob);
        } catch (err) {
          console.error('[Queue] Error processing memory queue job:', err);
        }
      }
    }
    isMemoryProcessing = false;
  });
}

import { NextResponse } from 'next/server';
import { getStorageBackendInfo, isMongoActive, isGuardrailEnforced } from '@/lib/db';
import { env } from '@/lib/env';

export async function GET() {
  const storageInfo = getStorageBackendInfo();
  const dbConnected = isMongoActive();
  const guardrailActive = isGuardrailEnforced();

  // In production, if database is offline and guardrail is active, mark system unhealthy
  const isHealthy = !guardrailActive || dbConnected;
  const status = dbConnected ? 'healthy' : (guardrailActive ? 'unhealthy' : 'degraded');
  const httpStatus = isHealthy ? 200 : 503;

  return NextResponse.json(
    {
      status,
      timestamp: new Date().toISOString(),
      uptimeSeconds: Math.floor(process.uptime()),
      environment: process.env.NODE_ENV || 'development',
      storage: {
        backend: storageInfo.backend,
        isAvailable: storageInfo.isAvailable,
        guardrailEnforced: storageInfo.guardrailEnforced,
        policy: guardrailActive
          ? 'STRICT_PRODUCTION (In-memory fallback strictly prohibited)'
          : 'DEVELOPMENT_FALLBACK (In-memory fallback permitted)',
      },
      subsystems: {
        database: {
          connected: dbConnected,
          type: storageInfo.backend,
        },
        queue: {
          backend: env.ENABLE_IN_MEMORY_QUEUE_FALLBACK ? 'in-memory-fallback-ready' : 'redis-strict',
        },
        aiAnalyst: {
          provider: env.AI_PROVIDER,
          model: env.AI_MODEL,
        },
        billing: {
          configured: Boolean(process.env.STRIPE_SECRET_KEY),
          mode: process.env.MOCK_STRIPE ? 'mock' : (process.env.STRIPE_SECRET_KEY ? 'live' : 'unconfigured'),
        },
      },
    },
    { status: httpStatus }
  );
}

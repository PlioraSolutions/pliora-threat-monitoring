import { z } from 'zod';
import fs from 'fs';
import path from 'path';

// If running outside Next.js (e.g. standalone test runner or worker), load .env.local
if (!process.env.NEXTAUTH_SECRET) {
  try {
    const envPath = path.resolve(process.cwd(), '.env.local');
    if (fs.existsSync(envPath)) {
      const content = fs.readFileSync(envPath, 'utf8');
      for (const line of content.split('\n')) {
        const match = line.match(/^\s*([\w.-]+)\s*=\s*(.*)?\s*$/);
        if (match) {
          const key = match[1];
          let val = match[2]?.trim() || '';
          if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
            val = val.slice(1, -1);
          }
          if (!process.env[key]) {
            process.env[key] = val;
          }
        }
      }
    }
  } catch {}
}

const envSchema = z.object({
  MONGODB_URI: z.string().default('mongodb://localhost:27017/pliora_threat_monitor'),
  REDIS_URL: z.string().default('redis://localhost:6379'),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  NEXTAUTH_SECRET: z.string().default('development_secret_key_change_in_production_12345'),
  JWT_SECRET: z.string().default('pliora_default_jwt_secret_key_32_chars_minimum_safe'),
  SCAN_WORKER_CONCURRENCY: z.coerce.number().default(5),
  ENABLE_IN_MEMORY_QUEUE_FALLBACK: z.coerce.boolean().default(true),
  GEMINI_API_KEY: z.string().optional(),
  OPENAI_API_KEY: z.string().optional(),
  AI_PROVIDER: z.enum(['gemini', 'openai', 'mock']).default('gemini'),
  AI_MODEL: z.string().default('gemini-1.5-flash'),
  AI_REQUEST_TIMEOUT_MS: z.coerce.number().default(10000),
  STRIPE_SECRET_KEY: z.string().optional(),
  STRIPE_WEBHOOK_SECRET: z.string().optional(),
  STRIPE_PRICE_STARTER_MONTHLY: z.string().optional(),
  STRIPE_PRICE_BUSINESS_MONTHLY: z.string().optional(),
  STRIPE_PRICE_PRO_MONTHLY: z.string().optional(),
  ALLOW_IN_MEMORY_STORE: z.string().optional(),
  ERROR_TRACKING_WEBHOOK_URL: z.string().optional(),
  HIBP_API_KEY: z.string().optional(),
  VIRUSTOTAL_API_KEY: z.string().optional(),
  GITHUB_TOKEN: z.string().optional(),
  EVIDENCE_RETENTION_DAYS: z.coerce.number().default(90),
  CANCELLED_ORG_RETENTION_DAYS: z.coerce.number().default(30),
});

export const env = envSchema.parse({
  MONGODB_URI: process.env.MONGODB_URI,
  REDIS_URL: process.env.REDIS_URL,
  NODE_ENV: process.env.NODE_ENV,
  NEXTAUTH_SECRET: process.env.NEXTAUTH_SECRET,
  JWT_SECRET: process.env.JWT_SECRET || process.env.NEXTAUTH_SECRET,
  SCAN_WORKER_CONCURRENCY: process.env.SCAN_WORKER_CONCURRENCY,
  ENABLE_IN_MEMORY_QUEUE_FALLBACK: process.env.ENABLE_IN_MEMORY_QUEUE_FALLBACK,
  GEMINI_API_KEY: process.env.GEMINI_API_KEY,
  OPENAI_API_KEY: process.env.OPENAI_API_KEY,
  AI_PROVIDER: (process.env.AI_PROVIDER as any) || 'gemini',
  AI_MODEL: process.env.AI_MODEL || 'gemini-1.5-flash',
  AI_REQUEST_TIMEOUT_MS: process.env.AI_REQUEST_TIMEOUT_MS || 10000,
  STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY,
  STRIPE_WEBHOOK_SECRET: process.env.STRIPE_WEBHOOK_SECRET,
  STRIPE_PRICE_STARTER_MONTHLY: process.env.STRIPE_PRICE_STARTER_MONTHLY,
  STRIPE_PRICE_BUSINESS_MONTHLY: process.env.STRIPE_PRICE_BUSINESS_MONTHLY,
  STRIPE_PRICE_PRO_MONTHLY: process.env.STRIPE_PRICE_PRO_MONTHLY,
  ALLOW_IN_MEMORY_STORE: process.env.ALLOW_IN_MEMORY_STORE,
  ERROR_TRACKING_WEBHOOK_URL: process.env.ERROR_TRACKING_WEBHOOK_URL,
  HIBP_API_KEY: process.env.HIBP_API_KEY,
  VIRUSTOTAL_API_KEY: process.env.VIRUSTOTAL_API_KEY,
  GITHUB_TOKEN: process.env.GITHUB_TOKEN,
  EVIDENCE_RETENTION_DAYS: process.env.EVIDENCE_RETENTION_DAYS || 90,
  CANCELLED_ORG_RETENTION_DAYS: process.env.CANCELLED_ORG_RETENTION_DAYS || 30,
});

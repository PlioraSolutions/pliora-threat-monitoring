import mongoose from 'mongoose';
import { env } from './env';

interface MongooseCache {
  conn: typeof mongoose | null;
  promise: Promise<typeof mongoose> | null;
  isAvailable: boolean | null;
}

declare global {
  // eslint-disable-next-line no-var
  var mongooseCache: MongooseCache | undefined;
}

let cached = global.mongooseCache;

if (!cached) {
  cached = global.mongooseCache = { conn: null, promise: null, isAvailable: null };
}

export function isProductionEnvironment(): boolean {
  return process.env.NODE_ENV === 'production';
}

export function isGuardrailEnforced(): boolean {
  return isProductionEnvironment() && process.env.ALLOW_IN_MEMORY_STORE !== 'true';
}

export async function connectToDatabase(): Promise<typeof mongoose | null> {
  // 1. Guardrail against forced memory store in production
  if (process.env.FORCE_MEMORY_STORE === 'true') {
    if (isGuardrailEnforced()) {
      throw new Error(
        'FATAL PRODUCTION ERROR: FORCE_MEMORY_STORE was requested, but in-memory store is strictly prohibited in production without ALLOW_IN_MEMORY_STORE=true.'
      );
    }
    if (cached) cached.isAvailable = false;
    return null;
  }

  // 2. Allow retry if previously marked unavailable rather than permanently locking out
  if (cached!.isAvailable === false && !isProductionEnvironment()) {
    // Reset cache to allow reconnection attempt
    cached!.isAvailable = null;
  } else if (cached!.isAvailable === false && isGuardrailEnforced()) {
    throw new Error(
      'FATAL PRODUCTION ERROR: MongoDB is marked unavailable. In-memory fallback is strictly prohibited in production environment.'
    );
  }

  if (cached!.conn) {
    return cached!.conn;
  }

  if (!cached!.promise) {
    const opts: mongoose.ConnectOptions = {
      bufferCommands: false,
      serverSelectionTimeoutMS: 8000, // 8s connection window for Atlas TLS handshake
      socketTimeoutMS: 45000,
    };

    cached!.promise = mongoose.connect(env.MONGODB_URI, opts).then((mongooseInstance) => {
      cached!.isAvailable = true;
      console.log('✅ Connected to live MongoDB instance.');
      return mongooseInstance;
    });
  }

  try {
    cached!.conn = await cached!.promise;
    cached!.isAvailable = true;
  } catch (e: any) {
    cached!.promise = null;
    cached!.conn = null;
    cached!.isAvailable = false;

    // Production Guardrail (§1): Refuse to silently run in-memory store in production
    if (isGuardrailEnforced()) {
      throw new Error(
        `FATAL PRODUCTION ERROR: MongoDB connection failed (${e.message}). In-memory fallback is strictly prohibited in production environment.`
      );
    }

    console.warn(`⚠️  MongoDB is offline (${e.message}). Falling back to fast In-Memory Store for local testing.`);
    return null;
  }

  return cached!.conn;
}

/**
 * Explicit startup verification: verifies database connectivity and strictly refuses
 * to boot in production if MongoDB is offline.
 */
export async function assertDatabaseConnectionAtStartup(): Promise<{
  backend: 'mongodb' | 'in-memory';
  status: 'connected' | 'fallback';
}> {
  try {
    const conn = await connectToDatabase();
    if (conn && isMongoActive()) {
      return { backend: 'mongodb', status: 'connected' };
    }
    if (isGuardrailEnforced()) {
      throw new Error(
        'FATAL PRODUCTION ERROR: MongoDB connection could not be established at startup. In-memory fallback is prohibited in production.'
      );
    }
    return { backend: 'in-memory', status: 'fallback' };
  } catch (err: any) {
    if (isGuardrailEnforced()) {
      throw err;
    }
    return { backend: 'in-memory', status: 'fallback' };
  }
}

export function isMongoActive(): boolean {
  return cached?.isAvailable === true;
}

export function getStorageBackendInfo(): {
  backend: 'mongodb' | 'in-memory';
  isAvailable: boolean;
  guardrailEnforced: boolean;
  environment: string;
} {
  const active = isMongoActive();
  return {
    backend: active ? 'mongodb' : 'in-memory',
    isAvailable: active,
    guardrailEnforced: isGuardrailEnforced(),
    environment: process.env.NODE_ENV || 'development',
  };
}

export function resetDatabaseConnectionForTesting(): void {
  if (cached) {
    cached.conn = null;
    cached.promise = null;
    cached.isAvailable = null;
  }
}

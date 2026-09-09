import { NextRequest, NextResponse } from 'next/server';
import crypto from 'crypto';
import { z } from 'zod';
import { requireAuth } from '@/lib/auth';
import { isMongoActive } from '@/lib/db';
import { memoryStore } from '@/lib/store';
import { ApiKey } from '@/models/ApiKey';
import { AuditLog } from '@/models/AuditLog';

const createApiKeySchema = z.object({
  name: z.string().trim().min(1, 'Key name is required').max(100),
  role: z.enum(['VIEWER', 'ADMIN']).default('VIEWER'),
  expiresInDays: z.number().int().positive().optional(),
});

export async function GET(request: NextRequest) {
  try {
    const { user, organization: org } = await requireAuth(request);

    const membership = user.organizationMemberships?.find(
      (m: any) => m.organizationId?.toString() === org._id?.toString()
    );
    const role = membership?.role || user.role || 'VIEWER';
    if (role !== 'OWNER' && role !== 'ADMIN') {
      return NextResponse.json(
        { success: false, error: { code: 'FORBIDDEN', message: 'Only Organization Owners or Admins can view API keys.' } },
        { status: 403 }
      );
    }

    let keys: any[] = [];
    if (isMongoActive()) {
      keys = await ApiKey.find({ organizationId: org._id })
        .select('_id name keyPrefix role lastUsedAt expiresAt createdAt')
        .sort({ createdAt: -1 })
        .lean();
    } else {
      keys = Array.from(memoryStore.apiKeys.values())
        .filter((k) => k.organizationId.toString() === org._id.toString())
        .map((k) => ({
          _id: k._id || k.id,
          id: k._id || k.id,
          name: k.name,
          keyPrefix: k.keyPrefix,
          role: k.role,
          lastUsedAt: k.lastUsedAt,
          expiresAt: k.expiresAt,
          createdAt: k.createdAt,
        }))
        .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
    }

    return NextResponse.json({
      success: true,
      data: keys,
    });
  } catch (error: any) {
    const status = error.status || 500;
    return NextResponse.json(
      { success: false, error: { code: 'API_KEY_LIST_ERROR', message: error.message } },
      { status }
    );
  }
}

export async function POST(request: NextRequest) {
  try {
    const { user, organization: org } = await requireAuth(request);

    const membership = user.organizationMemberships?.find(
      (m: any) => m.organizationId?.toString() === org._id?.toString()
    );
    const role = membership?.role || user.role || 'VIEWER';
    if (role !== 'OWNER' && role !== 'ADMIN') {
      return NextResponse.json(
        { success: false, error: { code: 'FORBIDDEN', message: 'Only Organization Owners or Admins can generate API keys.' } },
        { status: 403 }
      );
    }

    const body = await request.json().catch(() => ({}));
    const parseResult = createApiKeySchema.safeParse(body);
    if (!parseResult.success) {
      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'VALIDATION_FAILED',
            message: parseResult.error.errors.map((e) => e.message).join(', '),
          },
        },
        { status: 400 }
      );
    }

    const { name, role: keyRole, expiresInDays } = parseResult.data;

    // Generate cryptographic secret with standard prefix
    const secretRandom = crypto.randomBytes(24).toString('hex');
    const fullApiKey = `plk_live_${secretRandom}`;
    const keyPrefix = fullApiKey.substring(0, 14); // e.g. "plk_live_a1b2c3"
    const hashedKey = crypto.createHash('sha256').update(fullApiKey).digest('hex');

    const expiresAt = expiresInDays
      ? new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000)
      : undefined;

    let keyRecord: any;
    if (isMongoActive()) {
      keyRecord = await ApiKey.create({
        organizationId: org._id,
        name,
        keyPrefix,
        hashedKey,
        role: keyRole,
        expiresAt,
      });

      await AuditLog.create({
        organizationId: org._id,
        actorId: user._id?.toString() || user.id,
        action: 'API_KEY_CREATED',
        objectType: 'ApiKey',
        objectId: keyRecord._id.toString(),
        result: 'SUCCESS',
        details: { name, keyPrefix, role: keyRole },
      });
    } else {
      const keyId = `key-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
      keyRecord = {
        _id: keyId,
        id: keyId,
        organizationId: org._id,
        name,
        keyPrefix,
        hashedKey,
        role: keyRole,
        expiresAt,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      memoryStore.apiKeys.set(hashedKey, keyRecord);

      memoryStore.auditLogs.push({
        organizationId: org._id,
        actorId: user._id?.toString() || user.id,
        action: 'API_KEY_CREATED',
        objectType: 'ApiKey',
        objectId: keyId,
        result: 'SUCCESS',
        details: { name, keyPrefix, role: keyRole },
        createdAt: new Date(),
      });
    }

    return NextResponse.json(
      {
        success: true,
        data: {
          id: keyRecord._id || keyRecord.id,
          name: keyRecord.name,
          keyPrefix: keyRecord.keyPrefix,
          apiKey: fullApiKey, // ONLY returned once upon creation!
          role: keyRecord.role,
          expiresAt: keyRecord.expiresAt,
          createdAt: keyRecord.createdAt,
        },
      },
      { status: 201 }
    );
  } catch (error: any) {
    const status = error.status || 500;
    return NextResponse.json(
      { success: false, error: { code: 'API_KEY_CREATE_ERROR', message: error.message } },
      { status }
    );
  }
}

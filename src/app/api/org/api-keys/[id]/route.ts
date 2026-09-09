import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth';
import { isMongoActive } from '@/lib/db';
import { memoryStore } from '@/lib/store';
import { ApiKey } from '@/models/ApiKey';
import { AuditLog } from '@/models/AuditLog';

export async function DELETE(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const { user, organization: org } = await requireAuth(request);

    const membership = user.organizationMemberships?.find(
      (m: any) => m.organizationId?.toString() === org._id?.toString()
    );
    const role = membership?.role || user.role || 'VIEWER';
    if (role !== 'OWNER' && role !== 'ADMIN') {
      return NextResponse.json(
        { success: false, error: { code: 'FORBIDDEN', message: 'Only Organization Owners or Admins can revoke API keys.' } },
        { status: 403 }
      );
    }

    const { id } = params;

    if (isMongoActive()) {
      const keyRecord = await ApiKey.findOne({ _id: id, organizationId: org._id });
      if (!keyRecord) {
        return NextResponse.json(
          { success: false, error: { code: 'NOT_FOUND', message: 'API key not found or does not belong to organization.' } },
          { status: 404 }
        );
      }

      await ApiKey.deleteOne({ _id: id });
      await AuditLog.create({
        organizationId: org._id,
        actorId: user._id?.toString() || user.id,
        action: 'API_KEY_REVOKED',
        objectType: 'ApiKey',
        objectId: id,
        result: 'SUCCESS',
        details: { keyPrefix: keyRecord.keyPrefix },
      });
    } else {
      let foundHashedKey: string | null = null;
      let foundRecord: any = null;

      for (const [hash, record] of Array.from(memoryStore.apiKeys.entries())) {
        if ((record._id === id || record.id === id) && record.organizationId.toString() === org._id.toString()) {
          foundHashedKey = hash;
          foundRecord = record;
          break;
        }
      }

      if (!foundHashedKey) {
        return NextResponse.json(
          { success: false, error: { code: 'NOT_FOUND', message: 'API key not found or does not belong to organization.' } },
          { status: 404 }
        );
      }

      memoryStore.apiKeys.delete(foundHashedKey);
      memoryStore.auditLogs.push({
        organizationId: org._id,
        actorId: user._id?.toString() || user.id,
        action: 'API_KEY_REVOKED',
        objectType: 'ApiKey',
        objectId: id,
        result: 'SUCCESS',
        details: { keyPrefix: foundRecord.keyPrefix },
        createdAt: new Date(),
      });
    }

    return NextResponse.json({
      success: true,
      message: 'API key revoked successfully.',
    });
  } catch (error: any) {
    const status = error.status || 500;
    return NextResponse.json(
      { success: false, error: { code: 'API_KEY_REVOKE_ERROR', message: error.message } },
      { status }
    );
  }
}

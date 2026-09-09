import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { requireAuth } from '@/lib/auth';
import { isMongoActive } from '@/lib/db';
import { memoryStore } from '@/lib/store';
import { WebhookEndpoint } from '@/models/WebhookEndpoint';
import { AuditLog } from '@/models/AuditLog';
import { resolveAndPinTarget } from '@/lib/security';

const updateWebhookSchema = z.object({
  name: z.string().trim().min(1).max(100).optional(),
  url: z.string().trim().url().optional(),
  format: z.enum(['GENERIC', 'SLACK', 'JSON']).optional(),
  enabledTypes: z.array(z.string()).optional(),
  active: z.boolean().optional(),
});

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { user, organization: org } = await requireAuth(request);
    const { id } = await params;

    const membership = user.organizationMemberships?.find(
      (m: any) => m.organizationId?.toString() === org._id?.toString()
    );
    const role = membership?.role || user.role || 'VIEWER';
    if (role !== 'OWNER' && role !== 'ADMIN') {
      return NextResponse.json(
        { success: false, error: { code: 'FORBIDDEN', message: 'Only Organization Owners or Admins can view webhooks.' } },
        { status: 403 }
      );
    }

    let webhook: any = null;
    if (isMongoActive()) {
      webhook = await WebhookEndpoint.findOne({ _id: id, organizationId: org._id }).lean();
    } else {
      webhook = memoryStore.webhooks.get(id);
      if (webhook && webhook.organizationId.toString() !== org._id.toString()) {
        webhook = null;
      }
    }

    if (!webhook) {
      return NextResponse.json(
        { success: false, error: { code: 'NOT_FOUND', message: 'Webhook endpoint not found' } },
        { status: 404 }
      );
    }

    return NextResponse.json({
      success: true,
      data: {
        _id: webhook._id || webhook.id,
        id: webhook._id || webhook.id,
        name: webhook.name,
        url: webhook.url,
        format: webhook.format,
        enabledTypes: webhook.enabledTypes,
        active: webhook.active,
        secretMasked: webhook.secret ? `${webhook.secret.substring(0, 15)}...****` : null,
        createdAt: webhook.createdAt,
        updatedAt: webhook.updatedAt,
      },
    });
  } catch (error: any) {
    const status = error.status || 500;
    return NextResponse.json(
      { success: false, error: { code: 'WEBHOOK_GET_ERROR', message: error.message } },
      { status }
    );
  }
}

export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { user, organization: org } = await requireAuth(request);
    const { id } = await params;

    const membership = user.organizationMemberships?.find(
      (m: any) => m.organizationId?.toString() === org._id?.toString()
    );
    const role = membership?.role || user.role || 'VIEWER';
    if (role !== 'OWNER' && role !== 'ADMIN') {
      return NextResponse.json(
        { success: false, error: { code: 'FORBIDDEN', message: 'Only Organization Owners or Admins can update webhooks.' } },
        { status: 403 }
      );
    }

    const body = await request.json().catch(() => ({}));
    const parseResult = updateWebhookSchema.safeParse(body);
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

    const updates = parseResult.data;

    // If URL is being updated, enforce SSRF validation
    if (updates.url) {
      let parsedUrl: URL;
      try {
        parsedUrl = new URL(updates.url);
      } catch {
        return NextResponse.json(
          { success: false, error: { code: 'INVALID_URL', message: 'Invalid URL format' } },
          { status: 400 }
        );
      }

      if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
        return NextResponse.json(
          { success: false, error: { code: 'UNSUPPORTED_PROTOCOL', message: 'Only HTTP and HTTPS webhook targets are supported' } },
          { status: 400 }
        );
      }

      try {
        await resolveAndPinTarget(parsedUrl.hostname);
      } catch (ssrfErr: any) {
        return NextResponse.json(
          {
            success: false,
            error: {
              code: 'SSRF_VALIDATION_FAILED',
              message: ssrfErr.message || 'Webhook URL failed SSRF safety checks.',
            },
          },
          { status: 400 }
        );
      }
    }

    let updatedDoc: any = null;

    if (isMongoActive()) {
      updatedDoc = await WebhookEndpoint.findOneAndUpdate(
        { _id: id, organizationId: org._id },
        { $set: updates },
        { new: true }
      ).lean();

      if (!updatedDoc) {
        return NextResponse.json(
          { success: false, error: { code: 'NOT_FOUND', message: 'Webhook endpoint not found' } },
          { status: 404 }
        );
      }

      await AuditLog.create({
        organizationId: org._id,
        actorId: user._id || user.id,
        action: 'WEBHOOK_ENDPOINT_UPDATED',
        objectType: 'WebhookEndpoint',
        objectId: id,
        result: 'SUCCESS',
        details: { updates, actorEmail: user.email },
      });
    } else {
      const existing = memoryStore.webhooks.get(id);
      if (!existing || existing.organizationId.toString() !== org._id.toString()) {
        return NextResponse.json(
          { success: false, error: { code: 'NOT_FOUND', message: 'Webhook endpoint not found' } },
          { status: 404 }
        );
      }

      updatedDoc = {
        ...existing,
        ...updates,
        updatedAt: new Date(),
      };
      memoryStore.webhooks.set(id, updatedDoc);

      memoryStore.auditLogs.push({
        organizationId: org._id || org.id,
        actorId: user._id || user.id,
        action: 'WEBHOOK_ENDPOINT_UPDATED',
        objectType: 'WebhookEndpoint',
        objectId: id,
        result: 'SUCCESS',
        details: { updates, actorEmail: user.email },
        createdAt: new Date(),
      });
    }

    return NextResponse.json({
      success: true,
      data: {
        _id: updatedDoc._id || updatedDoc.id,
        id: updatedDoc._id || updatedDoc.id,
        name: updatedDoc.name,
        url: updatedDoc.url,
        format: updatedDoc.format,
        enabledTypes: updatedDoc.enabledTypes,
        active: updatedDoc.active,
        secretMasked: updatedDoc.secret ? `${updatedDoc.secret.substring(0, 15)}...****` : null,
        updatedAt: updatedDoc.updatedAt,
      },
    });
  } catch (error: any) {
    const status = error.status || 500;
    return NextResponse.json(
      { success: false, error: { code: 'WEBHOOK_UPDATE_ERROR', message: error.message } },
      { status }
    );
  }
}

export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { user, organization: org } = await requireAuth(request);
    const { id } = await params;

    const membership = user.organizationMemberships?.find(
      (m: any) => m.organizationId?.toString() === org._id?.toString()
    );
    const role = membership?.role || user.role || 'VIEWER';
    if (role !== 'OWNER' && role !== 'ADMIN') {
      return NextResponse.json(
        { success: false, error: { code: 'FORBIDDEN', message: 'Only Organization Owners or Admins can delete webhooks.' } },
        { status: 403 }
      );
    }

    if (isMongoActive()) {
      const deleted = await WebhookEndpoint.findOneAndDelete({ _id: id, organizationId: org._id });
      if (!deleted) {
        return NextResponse.json(
          { success: false, error: { code: 'NOT_FOUND', message: 'Webhook endpoint not found' } },
          { status: 404 }
        );
      }

      await AuditLog.create({
        organizationId: org._id,
        actorId: user._id || user.id,
        action: 'WEBHOOK_ENDPOINT_DELETED',
        objectType: 'WebhookEndpoint',
        objectId: id,
        result: 'SUCCESS',
        details: { deletedEndpointName: deleted.name, actorEmail: user.email },
      });
    } else {
      const existing = memoryStore.webhooks.get(id);
      if (!existing || existing.organizationId.toString() !== org._id.toString()) {
        return NextResponse.json(
          { success: false, error: { code: 'NOT_FOUND', message: 'Webhook endpoint not found' } },
          { status: 404 }
        );
      }

      memoryStore.webhooks.delete(id);
      memoryStore.auditLogs.push({
        organizationId: org._id || org.id,
        actorId: user._id || user.id,
        action: 'WEBHOOK_ENDPOINT_DELETED',
        objectType: 'WebhookEndpoint',
        objectId: id,
        result: 'SUCCESS',
        details: { deletedEndpointName: existing.name, actorEmail: user.email },
        createdAt: new Date(),
      });
    }

    return NextResponse.json({
      success: true,
      data: { id, deleted: true },
    });
  } catch (error: any) {
    const status = error.status || 500;
    return NextResponse.json(
      { success: false, error: { code: 'WEBHOOK_DELETE_ERROR', message: error.message } },
      { status }
    );
  }
}

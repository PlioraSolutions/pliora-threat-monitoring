import { NextRequest, NextResponse } from 'next/server';
import crypto from 'crypto';
import { z } from 'zod';
import { requireAuth } from '@/lib/auth';
import { isMongoActive } from '@/lib/db';
import { memoryStore } from '@/lib/store';
import { WebhookEndpoint } from '@/models/WebhookEndpoint';
import { AuditLog } from '@/models/AuditLog';
import { resolveAndPinTarget } from '@/lib/security';
import { DEFAULT_ALERT_SETTINGS } from '@/lib/alerts/rules';

const createWebhookSchema = z.object({
  name: z.string().trim().min(1, 'Webhook name is required').max(100),
  url: z.string().trim().url('Valid webhook destination URL is required'),
  format: z.enum(['GENERIC', 'SLACK', 'JSON']).default('GENERIC'),
  enabledTypes: z.array(z.string()).optional(),
  active: z.boolean().default(true),
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
        { success: false, error: { code: 'FORBIDDEN', message: 'Only Organization Owners or Admins can view webhooks.' } },
        { status: 403 }
      );
    }

    let webhooks: any[] = [];
    if (isMongoActive()) {
      webhooks = await WebhookEndpoint.find({ organizationId: org._id })
        .sort({ createdAt: -1 })
        .lean();
    } else {
      webhooks = Array.from(memoryStore.webhooks.values())
        .filter((w) => w.organizationId.toString() === org._id.toString())
        .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
    }

    // Mask secrets for display
    const masked = webhooks.map((w) => {
      const maskedVal = w.secret ? `${w.secret.substring(0, 15)}...****` : null;
      return {
        _id: w._id || w.id,
        id: w._id || w.id,
        name: w.name,
        url: w.url,
        format: w.format,
        enabledTypes: w.enabledTypes,
        active: w.active,
        secret: maskedVal,
        secretMasked: maskedVal,
        createdAt: w.createdAt,
        updatedAt: w.updatedAt,
      };
    });

    return NextResponse.json({
      success: true,
      data: masked,
    });
  } catch (error: any) {
    const status = error.status || 500;
    return NextResponse.json(
      { success: false, error: { code: 'WEBHOOK_LIST_ERROR', message: error.message } },
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
        { success: false, error: { code: 'FORBIDDEN', message: 'Only Organization Owners or Admins can create webhooks.' } },
        { status: 403 }
      );
    }

    const body = await request.json().catch(() => ({}));
    const parseResult = createWebhookSchema.safeParse(body);
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

    const { name, url, format, enabledTypes, active } = parseResult.data;

    // =========================================================================
    // MANDATORY SSRF VALIDATION (§1.1):
    // Customer-supplied webhook URL must point to a publicly routable target.
    // Reject loopback (127.0.0.1), RFC1918 subnets, and cloud metadata (169.254.169.254).
    // =========================================================================
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(url);
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
            message: ssrfErr.message || 'Webhook URL failed SSRF safety checks. Target must be a public external host.',
          },
        },
        { status: 400 }
      );
    }

    // Generate cryptographic signing secret (whsec_live_...)
    const secretRandom = crypto.randomBytes(24).toString('hex');
    const fullSecret = `whsec_live_${secretRandom}`;

    const effectiveTypes = enabledTypes && enabledTypes.length > 0
      ? enabledTypes
      : DEFAULT_ALERT_SETTINGS.enabledTypes;

    let webhookDoc: any = null;
    const webhookId = new (require('mongoose').Types.ObjectId)();

    if (isMongoActive()) {
      webhookDoc = await WebhookEndpoint.create({
        _id: webhookId,
        organizationId: org._id,
        name,
        url,
        format,
        enabledTypes: effectiveTypes,
        secret: fullSecret,
        active,
      });

      await AuditLog.create({
        organizationId: org._id,
        actorId: user._id || user.id,
        action: 'WEBHOOK_ENDPOINT_CREATED',
        objectType: 'WebhookEndpoint',
        objectId: webhookId.toString(),
        result: 'SUCCESS',
        details: { name, url, format, actorEmail: user.email },
      });
    } else {
      webhookDoc = {
        _id: webhookId.toString(),
        id: webhookId.toString(),
        organizationId: org._id || org.id,
        name,
        url,
        format,
        enabledTypes: effectiveTypes,
        secret: fullSecret,
        active,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      memoryStore.webhooks.set(webhookDoc._id, webhookDoc);

      memoryStore.auditLogs.push({
        organizationId: org._id || org.id,
        actorId: user._id || user.id,
        action: 'WEBHOOK_ENDPOINT_CREATED',
        objectType: 'WebhookEndpoint',
        objectId: webhookDoc._id,
        result: 'SUCCESS',
        details: { name, url, format, actorEmail: user.email },
        createdAt: new Date(),
      });
    }

    return NextResponse.json(
      {
        success: true,
        data: {
          _id: webhookDoc._id,
          id: webhookDoc._id,
          name: webhookDoc.name,
          url: webhookDoc.url,
          format: webhookDoc.format,
          enabledTypes: webhookDoc.enabledTypes,
          active: webhookDoc.active,
          secret: fullSecret, // ONLY returned once upon creation!
          createdAt: webhookDoc.createdAt,
        },
      },
      { status: 201 }
    );
  } catch (error: any) {
    const status = error.status || 500;
    return NextResponse.json(
      { success: false, error: { code: 'WEBHOOK_CREATE_ERROR', message: error.message } },
      { status }
    );
  }
}

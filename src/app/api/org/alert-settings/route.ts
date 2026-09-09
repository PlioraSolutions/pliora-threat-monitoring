import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { requireAuth } from '@/lib/auth';
import { isMongoActive } from '@/lib/db';
import { memoryStore } from '@/lib/store';
import { Organization } from '@/models/Organization';
import { AuditLog } from '@/models/AuditLog';
import { getOrganizationAlertSettings } from '@/lib/alerts/service';
import { DEFAULT_ALERT_SETTINGS } from '@/lib/alerts/rules';

const updateSettingsSchema = z.object({
  enabledTypes: z
    .array(
      z.enum([
        'NEW_CRITICAL_FINDING',
        'NEW_HIGH_FINDING',
        'FINDING_AUTO_REOPENED',
        'NEW_ASSET_DISCOVERED',
        'SCAN_FAILED',
        'THREAT_DETECTED',
      ])
    )
    .optional(),
  minRiskScore: z.number().min(0).max(100).optional(),
  additionalEmails: z.array(z.string().email()).optional(),
  sendToAdmins: z.boolean().optional(),
  webhookUrl: z.string().url().optional().nullable(),
  webhookSecret: z.string().min(8).optional().nullable(),
  webhookChannel: z.enum(['GENERIC', 'SLACK']).optional(),
});

export async function GET(request: NextRequest) {
  try {
    const { organization: org } = await requireAuth(request);
    const settings = await getOrganizationAlertSettings(org._id.toString());
    return NextResponse.json({ success: true, data: settings });
  } catch (error: any) {
    return NextResponse.json(
      { success: false, error: { code: 'ALERT_SETTINGS_ERROR', message: error.message } },
      { status: 500 }
    );
  }
}

export async function PATCH(request: NextRequest) {
  try {
    const { user, organization: org } = await requireAuth(request);

    // 1. Role-based authorization: Only OWNER and ADMIN can mutate alert settings (§4)
    const membership = user.organizationMemberships?.find(
      (m: any) => m.organizationId?.toString() === org._id.toString()
    );
    const userRole = membership?.role || user.role;

    if (userRole !== 'OWNER' && userRole !== 'ADMIN') {
      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'INSUFFICIENT_PERMISSIONS',
            message: `Role "${userRole}" cannot modify organization alert preferences. Requires OWNER or ADMIN.`,
          },
        },
        { status: 403 }
      );
    }

    const body = await request.json();
    const parseResult = updateSettingsSchema.safeParse(body);
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

    const currentSettings = await getOrganizationAlertSettings(org._id.toString());
    const updatedSettings = {
      enabledTypes: parseResult.data.enabledTypes ?? currentSettings.enabledTypes,
      minRiskScore: parseResult.data.minRiskScore ?? currentSettings.minRiskScore,
      additionalEmails: parseResult.data.additionalEmails ?? currentSettings.additionalEmails,
      sendToAdmins: parseResult.data.sendToAdmins ?? currentSettings.sendToAdmins,
      webhookUrl: parseResult.data.webhookUrl !== undefined ? (parseResult.data.webhookUrl || undefined) : currentSettings.webhookUrl,
      webhookSecret: parseResult.data.webhookSecret !== undefined ? (parseResult.data.webhookSecret || undefined) : currentSettings.webhookSecret,
      webhookChannel: parseResult.data.webhookChannel ?? currentSettings.webhookChannel ?? 'GENERIC',
    };

    if (isMongoActive()) {
      const orgDoc = await Organization.findById(org._id);
      if (orgDoc) {
        orgDoc.alertSettings = updatedSettings;
        await orgDoc.save();
      }

      await AuditLog.create({
        organizationId: org._id,
        actorId: user._id.toString(),
        action: 'ALERT_SETTINGS_UPDATED',
        objectType: 'Organization',
        objectId: org._id.toString(),
        result: 'SUCCESS',
        details: { updatedSettings },
      });
    } else {
      const orgDoc = memoryStore.organizations.get(org._id.toString());
      if (orgDoc) {
        orgDoc.alertSettings = updatedSettings;
        memoryStore.organizations.set(org._id.toString(), orgDoc);
      }

      memoryStore.auditLogs.push({
        organizationId: org._id,
        actorId: user._id.toString(),
        action: 'ALERT_SETTINGS_UPDATED',
        objectType: 'Organization',
        objectId: org._id.toString(),
        result: 'SUCCESS',
        details: { updatedSettings },
        createdAt: new Date(),
      });
    }

    return NextResponse.json({
      success: true,
      data: updatedSettings,
    });
  } catch (error: any) {
    return NextResponse.json(
      { success: false, error: { code: 'ALERT_SETTINGS_UPDATE_ERROR', message: error.message } },
      { status: 500 }
    );
  }
}

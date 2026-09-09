import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth';
import { Asset } from '@/models/Asset';
import { isMongoActive } from '@/lib/db';
import { memoryStore } from '@/lib/store';

export async function GET(request: NextRequest) {
  try {
    const { user, organization: org } = await requireAuth(request);
    let monitoredCount = 0;

    if (isMongoActive()) {
      monitoredCount = await Asset.countDocuments({
        organizationId: org._id,
        type: 'ROOT_DOMAIN',
      });
    } else {
      monitoredCount = Array.from(memoryStore.assets.values()).filter(
        (a) => a.organizationId === org._id && a.type === 'ROOT_DOMAIN'
      ).length;
    }

    return NextResponse.json({
      success: true,
      data: {
        id: org._id || org.id,
        name: org.name,
        slug: org.slug,
        plan: org.plan,
        scanQuotas: org.scanQuotas,
        settings: org.settings,
        reportBranding: org.reportBranding || { whiteLabelEnabled: false },
        subscriptionStatus: org.subscriptionStatus || 'ACTIVE',
        monitoredCount,
      },
    });
  } catch (error: any) {
    return NextResponse.json(
      { success: false, error: { code: 'ORG_FETCH_ERROR', message: error.message } },
      { status: error.status || 500 }
    );
  }
}

export async function PATCH(request: NextRequest) {
  try {
    const { user, organization: org } = await requireAuth(request);

    // Only OWNER and ADMIN can update organization settings
    const membership = user.organizationMemberships?.find(
      (m: any) => m.organizationId?.toString() === org._id?.toString()
    );
    const role = membership?.role || user.role || 'VIEWER';
    if (role !== 'OWNER' && role !== 'ADMIN') {
      return NextResponse.json(
        { success: false, error: { code: 'FORBIDDEN', message: 'Only Organization Owners or Admins can update settings.' } },
        { status: 403 }
      );
    }

    const body = await request.json();

    // Server-side tier gating for White-Label Report Branding (§5)
    if (body.reportBranding?.whiteLabelEnabled) {
      const allowed = org.plan === 'BUSINESS' || org.plan === 'PRO';
      if (!allowed) {
        return NextResponse.json(
          {
            success: false,
            error: {
              code: 'UPGRADE_REQUIRED',
              message: 'Custom white-label report branding is exclusively available on Business and Pro tiers. Please upgrade your plan to unlock this feature.',
            },
          },
          { status: 403 }
        );
      }
    }

    const updates: Record<string, any> = {};
    if (body.reportBranding) {
      updates.reportBranding = {
        ...(org.reportBranding || {}),
        ...body.reportBranding,
      };
    }
    if (body.name) updates.name = body.name.trim();

    if (isMongoActive()) {
      await import('@/models/Organization').then(({ Organization }) =>
        Organization.findByIdAndUpdate(org._id, { $set: updates })
      );
    } else {
      const existing = memoryStore.organizations.get(org._id || org.id) || {};
      const updated = { ...existing, ...updates, updatedAt: new Date() };
      memoryStore.organizations.set(org._id || org.id, updated);
      if (existing.slug) memoryStore.organizations.set(existing.slug, updated);
    }

    return NextResponse.json({
      success: true,
      data: {
        message: 'Organization updated successfully.',
        updates,
      },
    });
  } catch (error: any) {
    return NextResponse.json(
      { success: false, error: { code: 'ORG_UPDATE_ERROR', message: error.message } },
      { status: error.status || 500 }
    );
  }
}

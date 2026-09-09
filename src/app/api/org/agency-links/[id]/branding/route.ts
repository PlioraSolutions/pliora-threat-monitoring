import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth';
import { isMongoActive } from '@/lib/db';
import { memoryStore } from '@/lib/store';
import { AgencyClientLink } from '@/models/AgencyClientLink';
import { AuditLog } from '@/models/AuditLog';

interface RouteContext {
  params: Promise<{ id: string }>;
}

export async function PATCH(request: NextRequest, context: RouteContext) {
  try {
    const { user, organization: clientOrg } = await requireAuth(request);
    const { id: linkId } = await context.params;

    // Role check: Only OWNER or ADMIN of the client organization
    const membership = user.organizationMemberships?.find(
      (m: any) => m.organizationId?.toString() === clientOrg._id?.toString()
    );
    const role = membership?.role || user.role || 'VIEWER';
    if (role !== 'OWNER' && role !== 'ADMIN') {
      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'INSUFFICIENT_PERMISSIONS',
            message: 'Only Client Organization Owners and Admins can update agency branding delegation.',
          },
        },
        { status: 403 }
      );
    }

    const body = await request.json();
    const { delegateBranding } = body;

    if (typeof delegateBranding !== 'boolean') {
      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'VALIDATION_FAILED',
            message: 'delegateBranding boolean is required.',
          },
        },
        { status: 400 }
      );
    }

    const clientOrgIdStr = (clientOrg._id || clientOrg.id).toString();

    // 1. Locate the link
    let link: any = null;
    if (isMongoActive()) {
      link = await AgencyClientLink.findOne({
        _id: linkId,
        clientOrgId: clientOrg._id,
      });
    } else {
      const links = Array.from(memoryStore.agencyClientLinks.values());
      link = links.find(
        (l: any) =>
          (l._id?.toString() === linkId || l.id === linkId) &&
          (l.clientOrgId?.toString() === clientOrgIdStr || l.clientOrgId === clientOrgIdStr)
      );
    }

    if (!link) {
      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'LINK_NOT_FOUND',
            message: 'Agency link not found.',
          },
        },
        { status: 404 }
      );
    }

    // 2. Update delegateBranding flag
    const now = new Date();
    if (isMongoActive()) {
      link.delegateBranding = delegateBranding;
      await link.save();
    } else {
      link.delegateBranding = delegateBranding;
      link.updatedAt = now;
      memoryStore.agencyClientLinks.set(linkId, link);
    }

    // 3. AuditLog
    const clientLog = {
      organizationId: clientOrg._id || clientOrg.id,
      actorId: user.email || user._id,
      action: 'AGENCY_BRANDING_DELEGATED',
      objectType: 'AgencyClientLink',
      objectId: linkId,
      result: 'SUCCESS',
      details: {
        delegateBranding,
      },
      createdAt: now,
    };

    if (isMongoActive()) {
      await AuditLog.create(clientLog).catch(() => {});
    } else {
      memoryStore.auditLogs.push(clientLog);
    }

    return NextResponse.json({
      success: true,
      message: `Report branding delegation updated to ${delegateBranding}.`,
      data: {
        linkId,
        delegateBranding,
      },
    });
  } catch (error: any) {
    const status = error.status || 500;
    return NextResponse.json(
      { success: false, error: { code: 'UPDATE_BRANDING_ERROR', message: error.message } },
      { status }
    );
  }
}

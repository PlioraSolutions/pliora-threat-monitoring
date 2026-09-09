import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth';
import { isMongoActive } from '@/lib/db';
import { memoryStore } from '@/lib/store';
import { AgencyClientLink } from '@/models/AgencyClientLink';
import { AuditLog } from '@/models/AuditLog';

interface RouteContext {
  params: Promise<{ id: string }>;
}

export async function POST(request: NextRequest, context: RouteContext) {
  try {
    const { user, organization: clientOrg } = await requireAuth(request);
    const { id: linkId } = await context.params;

    // Role check: Only OWNER or ADMIN of the client organization can approve links (§1)
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
            message: 'Only Client Organization Owners and Admins can accept agency links.',
          },
        },
        { status: 403 }
      );
    }

    const clientOrgIdStr = (clientOrg._id || clientOrg.id).toString();

    // 1. Locate the pending link
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
            message: 'Agency link request not found.',
          },
        },
        { status: 404 }
      );
    }

    if (link.status === 'ACTIVE') {
      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'ALREADY_ACTIVE',
            message: 'This agency link is already active.',
          },
        },
        { status: 400 }
      );
    }

    // 2. Activate link (§1: explicit client approval required)
    const now = new Date();
    const userIdStr = (user._id || user.id).toString();
    const agencyOrgIdStr = (link.agencyOrgId?._id || link.agencyOrgId).toString();

    if (isMongoActive()) {
      link.status = 'ACTIVE';
      link.grantedByUserId = userIdStr;
      link.grantedAt = now;
      link.revokedAt = undefined;
      link.revokedByUserId = undefined;
      await link.save();
    } else {
      link.status = 'ACTIVE';
      link.grantedByUserId = userIdStr;
      link.grantedAt = now;
      link.revokedAt = undefined;
      link.revokedByUserId = undefined;
      link.updatedAt = now;
      memoryStore.agencyClientLinks.set(linkId, link);
    }

    // 3. Dual AuditLog
    const clientLog = {
      organizationId: clientOrg._id || clientOrg.id,
      actorId: user.email || user._id,
      action: 'AGENCY_LINK_ACCEPTED',
      objectType: 'AgencyClientLink',
      objectId: linkId,
      result: 'SUCCESS',
      details: {
        agencyOrgId: agencyOrgIdStr,
        scopes: link.scopes,
        approvedByRole: role,
      },
      createdAt: now,
    };

    const agencyLog = {
      organizationId: link.agencyOrgId?._id || link.agencyOrgId,
      actorId: user.email || user._id,
      action: 'AGENCY_LINK_ACCEPTED',
      objectType: 'AgencyClientLink',
      objectId: linkId,
      result: 'SUCCESS',
      details: {
        clientOrgId: clientOrgIdStr,
        clientName: clientOrg.name,
      },
      createdAt: now,
    };

    if (isMongoActive()) {
      await AuditLog.create(clientLog).catch(() => {});
      await AuditLog.create(agencyLog).catch(() => {});
    } else {
      memoryStore.auditLogs.push(clientLog);
      memoryStore.auditLogs.push(agencyLog);
    }

    return NextResponse.json({
      success: true,
      message: 'Agency link successfully accepted. Partner now has read-only access.',
      data: {
        linkId,
        status: 'ACTIVE',
        grantedAt: now,
        grantedByUserId: userIdStr,
      },
    });
  } catch (error: any) {
    const status = error.status || 500;
    return NextResponse.json(
      { success: false, error: { code: 'ACCEPT_LINK_ERROR', message: error.message } },
      { status }
    );
  }
}

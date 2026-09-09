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
    const { user, organization: agencyOrg } = await requireAuth(request);
    const { id: linkOrClientOrgId } = await context.params;

    // Role check: Only OWNER or ADMIN of the agency can revoke links
    const membership = user.organizationMemberships?.find(
      (m: any) => m.organizationId?.toString() === agencyOrg._id?.toString()
    );
    const role = membership?.role || user.role || 'VIEWER';
    if (role !== 'OWNER' && role !== 'ADMIN') {
      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'INSUFFICIENT_PERMISSIONS',
            message: 'Only agency Owners and Admins can revoke client links.',
          },
        },
        { status: 403 }
      );
    }

    const agencyOrgIdStr = (agencyOrg._id || agencyOrg.id).toString();

    // 1. Locate the link
    let link: any = null;
    if (isMongoActive()) {
      link = await AgencyClientLink.findOne({
        agencyOrgId: agencyOrg._id,
        $or: [
          { _id: linkOrClientOrgId },
          { clientOrgId: linkOrClientOrgId },
        ],
      });
    } else {
      const links = Array.from(memoryStore.agencyClientLinks.values());
      link = links.find(
        (l: any) =>
          (l.agencyOrgId?.toString() === agencyOrgIdStr || l.agencyOrgId === agencyOrgIdStr) &&
          (l._id?.toString() === linkOrClientOrgId ||
            l.id === linkOrClientOrgId ||
            l.clientOrgId?.toString() === linkOrClientOrgId ||
            l.clientOrgId === linkOrClientOrgId)
      );
    }

    if (!link) {
      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'LINK_NOT_FOUND',
            message: 'Agency client link not found.',
          },
        },
        { status: 404 }
      );
    }

    // 2. Immediate Revocation (§1 & §6: immediate and available to either party)
    const now = new Date();
    const clientOrgIdStr = (link.clientOrgId?._id || link.clientOrgId).toString();
    const linkIdStr = (link._id || link.id).toString();

    if (isMongoActive()) {
      link.status = 'REVOKED';
      link.revokedAt = now;
      link.revokedByUserId = (user._id || user.id).toString();
      await link.save();
    } else {
      link.status = 'REVOKED';
      link.revokedAt = now;
      link.revokedByUserId = (user._id || user.id).toString();
      link.updatedAt = now;
      memoryStore.agencyClientLinks.set(linkIdStr, link);
    }

    // 3. Dual Audit Logging (§6)
    const agencyLog = {
      organizationId: agencyOrg._id || agencyOrg.id,
      actorId: user.email || user._id,
      action: 'AGENCY_LINK_REVOKED',
      objectType: 'AgencyClientLink',
      objectId: linkIdStr,
      result: 'SUCCESS',
      details: {
        clientOrgId: clientOrgIdStr,
        revokedByRole: role,
        party: 'AGENCY',
      },
      createdAt: now,
    };

    const clientLog = {
      organizationId: link.clientOrgId?._id || link.clientOrgId,
      actorId: user.email || user._id,
      action: 'AGENCY_LINK_REVOKED',
      objectType: 'AgencyClientLink',
      objectId: linkIdStr,
      result: 'SUCCESS',
      details: {
        agencyOrgId: agencyOrgIdStr,
        agencyName: agencyOrg.name,
        party: 'AGENCY',
      },
      createdAt: now,
    };

    if (isMongoActive()) {
      await AuditLog.create(agencyLog).catch(() => {});
      await AuditLog.create(clientLog).catch(() => {});
    } else {
      memoryStore.auditLogs.push(agencyLog);
      memoryStore.auditLogs.push(clientLog);
    }

    return NextResponse.json({
      success: true,
      message: 'Client link successfully revoked. Access has been terminated immediately.',
      data: {
        linkId: linkIdStr,
        status: 'REVOKED',
        revokedAt: now,
      },
    });
  } catch (error: any) {
    const status = error.status || 500;
    return NextResponse.json(
      { success: false, error: { code: 'AGENCY_REVOKE_ERROR', message: error.message } },
      { status }
    );
  }
}

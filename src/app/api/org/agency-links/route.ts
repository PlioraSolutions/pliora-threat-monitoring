import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth';
import { isMongoActive } from '@/lib/db';
import { memoryStore } from '@/lib/store';
import { Organization } from '@/models/Organization';
import { AgencyClientLink } from '@/models/AgencyClientLink';
import { AuditLog } from '@/models/AuditLog';

export async function GET(request: NextRequest) {
  try {
    const { organization: clientOrg } = await requireAuth(request);
    const clientOrgIdStr = (clientOrg._id || clientOrg.id).toString();

    // 1. Fetch links for this client organization
    let links: any[] = [];
    if (isMongoActive()) {
      links = await AgencyClientLink.find({
        clientOrgId: clientOrg._id,
      })
        .sort({ createdAt: -1 })
        .lean();
    } else {
      links = Array.from(memoryStore.agencyClientLinks.values()).filter(
        (l: any) =>
          l.clientOrgId?.toString() === clientOrgIdStr || l.clientOrgId === clientOrgIdStr
      );
      links.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
    }

    // 2. Populate agency details
    const populatedLinks = await Promise.all(
      links.map(async (link: any) => {
        const agencyOrgIdStr = (link.agencyOrgId?._id || link.agencyOrgId).toString();
        let agency: any = null;

        if (isMongoActive()) {
          agency = await Organization.findById(agencyOrgIdStr)
            .select('name slug accountType reportBranding')
            .lean();
        } else {
          agency =
            memoryStore.organizations.get(agencyOrgIdStr) ||
            Array.from(memoryStore.organizations.values()).find(
              (o: any) => (o._id || o.id)?.toString() === agencyOrgIdStr
            );
        }

        return {
          linkId: (link._id || link.id).toString(),
          agencyOrgId: agencyOrgIdStr,
          agencyName: agency?.name || 'Unknown Agency',
          agencySlug: agency?.slug || 'agency',
          status: link.status,
          scopes: link.scopes || ['READ_ONLY'],
          delegateBranding: Boolean(link.delegateBranding),
          grantedAt: link.grantedAt,
          revokedAt: link.revokedAt,
          createdAt: link.createdAt,
        };
      })
    );

    // 3. Fetch recent agency data access logs (§3: surface access-log entries directly in settings)
    let accessLogs: any[] = [];
    if (isMongoActive()) {
      accessLogs = await AuditLog.find({
        organizationId: clientOrg._id,
        action: 'AGENCY_DATA_ACCESSED',
      })
        .sort({ createdAt: -1 })
        .limit(50)
        .lean();
    } else {
      accessLogs = (memoryStore.auditLogs || [])
        .filter(
          (log: any) =>
            (log.organizationId?.toString() === clientOrgIdStr ||
              log.organizationId === clientOrgIdStr) &&
            log.action === 'AGENCY_DATA_ACCESSED'
        )
        .sort((a: any, b: any) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
        .slice(0, 50);
    }

    return NextResponse.json({
      success: true,
      data: {
        links: populatedLinks,
        accessLogs: accessLogs.map((log: any) => ({
          id: (log._id || log.id || Math.random()).toString(),
          actor: log.actorId,
          timestamp: log.createdAt,
          agencyName: log.details?.agencyName || 'Partner Agency',
          path: log.details?.path || '/',
          scopes: log.details?.scopes || ['READ_ONLY'],
        })),
      },
    });
  } catch (error: any) {
    const status = error.status || 500;
    return NextResponse.json(
      { success: false, error: { code: 'CLIENT_LINKS_ERROR', message: error.message } },
      { status }
    );
  }
}

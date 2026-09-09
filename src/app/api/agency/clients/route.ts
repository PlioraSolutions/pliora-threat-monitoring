import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth';
import { isMongoActive } from '@/lib/db';
import { memoryStore } from '@/lib/store';
import { Organization } from '@/models/Organization';
import { AgencyClientLink } from '@/models/AgencyClientLink';
import { Finding } from '@/models/Finding';
import { Scan } from '@/models/Scan';
import { computeOrgRiskScore } from '@/lib/risk/orgScore';

export async function GET(request: NextRequest) {
  try {
    const { organization: agencyOrg } = await requireAuth(request);

    if (agencyOrg.accountType !== 'AGENCY') {
      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'FORBIDDEN',
            message: 'Only agency accounts can access the multi-client dashboard view.',
          },
        },
        { status: 403 }
      );
    }

    const agencyOrgIdStr = (agencyOrg._id || agencyOrg.id).toString();

    // 1. Fetch active links for this agency
    let activeLinks: any[] = [];
    if (isMongoActive()) {
      activeLinks = await AgencyClientLink.find({
        agencyOrgId: agencyOrg._id,
        status: 'ACTIVE',
      }).lean();
    } else {
      activeLinks = Array.from(memoryStore.agencyClientLinks.values()).filter(
        (l: any) =>
          (l.agencyOrgId?.toString() === agencyOrgIdStr || l.agencyOrgId === agencyOrgIdStr) &&
          l.status === 'ACTIVE'
      );
    }

    // 2. Aggregate portfolio metrics per client
    const clientSummaries = await Promise.all(
      activeLinks.map(async (link: any) => {
        const clientOrgIdStr = (link.clientOrgId?._id || link.clientOrgId).toString();

        let clientOrg: any = null;
        if (isMongoActive()) {
          clientOrg = await Organization.findById(clientOrgIdStr).lean();
        } else {
          clientOrg =
            memoryStore.organizations.get(clientOrgIdStr) ||
            Array.from(memoryStore.organizations.values()).find(
              (o: any) => (o._id || o.id)?.toString() === clientOrgIdStr
            );
        }

        if (!clientOrg) {
          return null;
        }

        // Live Risk Score & Posture
        const riskScoreData = await computeOrgRiskScore(clientOrgIdStr);

        // Open Findings counts (critical / high)
        let openCriticalCount = 0;
        let openHighCount = 0;
        let totalFindings = 0;

        if (isMongoActive()) {
          openCriticalCount = await Finding.countDocuments({
            organizationId: clientOrg._id,
            status: 'OPEN',
            severity: 'CRITICAL',
          });
          openHighCount = await Finding.countDocuments({
            organizationId: clientOrg._id,
            status: 'OPEN',
            severity: 'HIGH',
          });
          totalFindings = await Finding.countDocuments({
            organizationId: clientOrg._id,
            status: 'OPEN',
          });
        } else {
          const clientFindings = Array.from(memoryStore.findings.values()).filter(
            (f: any) =>
              (f.organizationId?.toString() === clientOrgIdStr || f.organizationId === clientOrgIdStr) &&
              f.status === 'OPEN'
          );
          openCriticalCount = clientFindings.filter((f: any) => f.severity === 'CRITICAL').length;
          openHighCount = clientFindings.filter((f: any) => f.severity === 'HIGH').length;
          totalFindings = clientFindings.length;
        }

        // Latest Scan
        let lastScanDate: Date | null = null;
        if (isMongoActive()) {
          const latestScan = await Scan.findOne({ organizationId: clientOrg._id })
            .sort({ completedAt: -1, createdAt: -1 })
            .lean();
          lastScanDate = latestScan?.completedAt || latestScan?.createdAt || null;
        } else {
          const clientScans = Array.from(memoryStore.scans.values()).filter(
            (s: any) => s.organizationId?.toString() === clientOrgIdStr || s.organizationId === clientOrgIdStr
          );
          if (clientScans.length > 0) {
            clientScans.sort(
              (a, b) =>
                new Date(b.completedAt || b.createdAt).getTime() -
                new Date(a.completedAt || a.createdAt).getTime()
            );
            lastScanDate = clientScans[0].completedAt || clientScans[0].createdAt || null;
          }
        }

        return {
          linkId: (link._id || link.id).toString(),
          clientOrgId: clientOrgIdStr,
          name: clientOrg.name,
          slug: clientOrg.slug,
          plan: clientOrg.plan || 'FREE',
          riskScore: riskScoreData.score,
          securityPosture: riskScoreData.securityPosture,
          grade: riskScoreData.grade,
          openCriticalCount,
          openHighCount,
          totalFindings,
          lastScanDate,
          delegateBranding: Boolean(link.delegateBranding),
          linkedAt: link.grantedAt || link.createdAt,
        };
      })
    );

    const validClients = clientSummaries.filter(Boolean);

    return NextResponse.json({
      success: true,
      data: {
        clients: validClients,
        totalActiveClients: validClients.length,
      },
    });
  } catch (error: any) {
    const status = error.status || 500;
    return NextResponse.json(
      { success: false, error: { code: 'AGENCY_CLIENTS_ERROR', message: error.message } },
      { status }
    );
  }
}

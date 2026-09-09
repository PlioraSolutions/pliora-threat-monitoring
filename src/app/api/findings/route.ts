import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth';
import { isMongoActive } from '@/lib/db';
import { memoryStore } from '@/lib/store';
import { Finding } from '@/models/Finding';
import { FindingSeverity } from '@/types';

const SEVERITY_RANKS: Record<FindingSeverity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFORMATIONAL: 1,
};

export async function GET(request: NextRequest) {
  try {
    const { organization: org } = await requireAuth(request);
    const { searchParams } = new URL(request.url);

    const severityFilter = searchParams.get('severity');
    const confidenceFilter = searchParams.get('confidence');
    const statusFilter = searchParams.get('status');
    const categoryFilter = searchParams.get('category');
    const assetIdFilter = searchParams.get('assetId');

    const page = Math.max(1, parseInt(searchParams.get('page') || '1', 10));
    const limit = Math.min(100, Math.max(1, parseInt(searchParams.get('limit') || '20', 10)));
    const skip = (page - 1) * limit;
    const sortBy = searchParams.get('sortBy') || 'severity';
    const sortOrder = (searchParams.get('sortOrder') || 'desc').toLowerCase();

    let allFindings: any[] = [];

    if (isMongoActive()) {
      const query: Record<string, any> = { organizationId: org._id };
      if (severityFilter) query.severity = severityFilter;
      if (confidenceFilter) query.confidence = confidenceFilter;
      if (statusFilter) query.status = statusFilter;
      if (categoryFilter) query.category = categoryFilter;
      if (assetIdFilter) query.assetId = assetIdFilter;

      allFindings = await Finding.find(query).lean();
    } else {
      const orgIdStr = org._id?.toString();
      allFindings = Array.from(memoryStore.findings.values()).filter(
        (f) => f.organizationId?.toString() === orgIdStr
      );

      if (severityFilter) allFindings = allFindings.filter((f) => f.severity === severityFilter);
      if (confidenceFilter) allFindings = allFindings.filter((f) => f.confidence === confidenceFilter);
      if (statusFilter) allFindings = allFindings.filter((f) => f.status === statusFilter);
      if (categoryFilter) allFindings = allFindings.filter((f) => f.category === categoryFilter);
      if (assetIdFilter) allFindings = allFindings.filter((f) => f.assetId?.toString() === assetIdFilter);
    }

    // Sort findings
    allFindings.sort((a, b) => {
      let comparison = 0;
      if (sortBy === 'severity') {
        const rankA = SEVERITY_RANKS[a.severity as FindingSeverity] || 0;
        const rankB = SEVERITY_RANKS[b.severity as FindingSeverity] || 0;
        comparison = rankB - rankA;
      } else if (sortBy === 'riskScore') {
        comparison = (b.riskScore || 0) - (a.riskScore || 0);
      } else if (sortBy === 'lastSeen') {
        comparison = new Date(b.lastSeen || 0).getTime() - new Date(a.lastSeen || 0).getTime();
      } else {
        comparison = new Date(b.createdAt || 0).getTime() - new Date(a.createdAt || 0).getTime();
      }
      return sortOrder === 'asc' ? -comparison : comparison;
    });

    const total = allFindings.length;
    const totalPages = Math.ceil(total / limit) || 1;
    const paginatedFindings = allFindings.slice(skip, skip + limit);

    return NextResponse.json({
      success: true,
      data: paginatedFindings,
      pagination: {
        page,
        limit,
        total,
        totalPages,
      },
    });
  } catch (error: any) {
    const status = error.status || 500;
    return NextResponse.json(
      { success: false, error: { code: 'FINDINGS_LIST_ERROR', message: error.message } },
      { status }
    );
  }
}

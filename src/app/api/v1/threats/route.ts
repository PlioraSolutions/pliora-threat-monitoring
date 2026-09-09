import { NextRequest } from 'next/server';
import { requireApiKeyAuth, formatApiResponse, formatApiErrorResponse } from '@/lib/auth/apiKeyAuth';
import { isMongoActive } from '@/lib/db';
import { memoryStore } from '@/lib/store';
import { Threat } from '@/models/Threat';

export async function GET(request: NextRequest) {
  try {
    const { organization: org, rateLimit } = await requireApiKeyAuth(request);
    const { searchParams } = new URL(request.url);

    const statusFilter = searchParams.get('status');
    const confidenceFilter = searchParams.get('confidence');
    const sourceFilter = searchParams.get('source');
    const rootDomainFilter = searchParams.get('relatedRootDomain');
    const search = searchParams.get('search') || searchParams.get('q');

    const page = Math.max(1, parseInt(searchParams.get('page') || '1', 10));
    const limit = Math.min(100, Math.max(1, parseInt(searchParams.get('limit') || '20', 10)));
    const skip = (page - 1) * limit;
    const sortBy = searchParams.get('sortBy') || 'corroborationScore';
    const sortOrder = (searchParams.get('sortOrder') || 'desc').toLowerCase();

    let allThreats: any[] = [];

    if (isMongoActive()) {
      const query: Record<string, any> = { organizationId: org._id };
      if (statusFilter) query.status = statusFilter;
      if (confidenceFilter) query.confidence = confidenceFilter;
      if (sourceFilter) query.source = sourceFilter;
      if (rootDomainFilter) query.relatedRootDomain = rootDomainFilter.toLowerCase().trim();
      if (search) query.indicator = { $regex: search, $options: 'i' };

      allThreats = await Threat.find(query).lean();
    } else {
      const orgIdStr = (org._id || org.id).toString();
      allThreats = Array.from(memoryStore.threats.values()).filter(
        (t) => t.organizationId?.toString() === orgIdStr
      );

      if (statusFilter) allThreats = allThreats.filter((t) => t.status === statusFilter);
      if (confidenceFilter) allThreats = allThreats.filter((t) => t.confidence === confidenceFilter);
      if (sourceFilter) allThreats = allThreats.filter((t) => t.source === sourceFilter);
      if (rootDomainFilter) {
        allThreats = allThreats.filter(
          (t) => t.relatedRootDomain?.toLowerCase() === rootDomainFilter.toLowerCase().trim()
        );
      }
      if (search) {
        const queryLower = search.toLowerCase();
        allThreats = allThreats.filter((t) => t.indicator?.toLowerCase().includes(queryLower));
      }
    }

    // Sort threats
    allThreats.sort((a, b) => {
      let comparison = 0;
      if (sortBy === 'corroborationScore') {
        comparison = (b.corroborationScore || 0) - (a.corroborationScore || 0);
      } else if (sortBy === 'lastSeen') {
        comparison = new Date(b.lastSeen || 0).getTime() - new Date(a.lastSeen || 0).getTime();
      } else if (sortBy === 'indicator') {
        comparison = (a.indicator || '').localeCompare(b.indicator || '');
      } else {
        comparison = new Date(b.createdAt || 0).getTime() - new Date(a.createdAt || 0).getTime();
      }
      return sortOrder === 'asc' ? -comparison : comparison;
    });

    const total = allThreats.length;
    const totalPages = Math.ceil(total / limit) || 1;
    const paginated = allThreats.slice(skip, skip + limit);

    return formatApiResponse(
      paginated,
      {
        total,
        page,
        limit,
        totalPages,
      },
      {
        'X-RateLimit-Limit': rateLimit.limit.toString(),
        'X-RateLimit-Remaining': rateLimit.remaining.toString(),
        'X-RateLimit-Reset': rateLimit.resetSeconds.toString(),
      }
    );
  } catch (error: any) {
    return formatApiErrorResponse(error);
  }
}

import { NextRequest } from 'next/server';
import { requireApiKeyAuth, formatApiResponse, formatApiErrorResponse } from '@/lib/auth/apiKeyAuth';
import { isMongoActive } from '@/lib/db';
import { memoryStore } from '@/lib/store';
import { Asset } from '@/models/Asset';

const IMPORTANCE_RANKS: Record<string, number> = {
  CRITICAL: 4,
  HIGH: 3,
  NORMAL: 2,
  LOW: 1,
};

export async function GET(request: NextRequest) {
  try {
    const { organization: org, rateLimit } = await requireApiKeyAuth(request);
    const { searchParams } = new URL(request.url);

    const typeFilter = searchParams.get('type');
    const statusFilter = searchParams.get('status') || searchParams.get('verificationStatus');
    const rootDomainFilter = searchParams.get('rootDomain');
    const importanceFilter = searchParams.get('importance');
    const search = searchParams.get('search') || searchParams.get('q');

    const page = Math.max(1, parseInt(searchParams.get('page') || '1', 10));
    const limit = Math.min(100, Math.max(1, parseInt(searchParams.get('limit') || '20', 10)));
    const skip = (page - 1) * limit;
    const sortBy = searchParams.get('sortBy') || 'createdAt';
    const sortOrder = (searchParams.get('sortOrder') || 'desc').toLowerCase();

    let allAssets: any[] = [];

    if (isMongoActive()) {
      const query: Record<string, any> = { organizationId: org._id };
      if (typeFilter) query.type = typeFilter;
      if (statusFilter) query.verificationStatus = statusFilter;
      if (rootDomainFilter) query.rootDomain = rootDomainFilter.toLowerCase().trim();
      if (importanceFilter) query.importance = importanceFilter;
      if (search) query.fqdn = { $regex: search, $options: 'i' };

      allAssets = await Asset.find(query).lean();
    } else {
      const orgIdStr = (org._id || org.id).toString();
      allAssets = Array.from(memoryStore.assets.values()).filter(
        (a) => a.organizationId?.toString() === orgIdStr
      );

      if (typeFilter) allAssets = allAssets.filter((a) => a.type === typeFilter);
      if (statusFilter) allAssets = allAssets.filter((a) => a.verificationStatus === statusFilter);
      if (rootDomainFilter) {
        allAssets = allAssets.filter(
          (a) => a.rootDomain?.toLowerCase() === rootDomainFilter.toLowerCase().trim()
        );
      }
      if (importanceFilter) allAssets = allAssets.filter((a) => a.importance === importanceFilter);
      if (search) {
        const queryLower = search.toLowerCase();
        allAssets = allAssets.filter((a) => a.fqdn?.toLowerCase().includes(queryLower));
      }
    }

    // Sort assets
    allAssets.sort((a, b) => {
      let comparison = 0;
      if (sortBy === 'importance') {
        const rankA = IMPORTANCE_RANKS[a.importance] || 0;
        const rankB = IMPORTANCE_RANKS[b.importance] || 0;
        comparison = rankB - rankA;
      } else if (sortBy === 'fqdn') {
        comparison = (a.fqdn || '').localeCompare(b.fqdn || '');
      } else if (sortBy === 'lastSeen') {
        comparison = new Date(b.lastSeen || 0).getTime() - new Date(a.lastSeen || 0).getTime();
      } else {
        comparison = new Date(b.createdAt || 0).getTime() - new Date(a.createdAt || 0).getTime();
      }
      return sortOrder === 'asc' ? -comparison : comparison;
    });

    const total = allAssets.length;
    const totalPages = Math.ceil(total / limit) || 1;
    const paginated = allAssets.slice(skip, skip + limit);

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

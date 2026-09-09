import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth';
import { isMongoActive } from '@/lib/db';
import { memoryStore } from '@/lib/store';
import { Alert } from '@/models/Alert';

export async function GET(request: NextRequest) {
  try {
    const { organization: org } = await requireAuth(request);
    const { searchParams } = new URL(request.url);

    const typeFilter = searchParams.get('type');
    const severityFilter = searchParams.get('severity');
    const statusFilter = searchParams.get('deliveryStatus');
    const page = Math.max(1, parseInt(searchParams.get('page') || '1', 10));
    const limit = Math.min(100, Math.max(1, parseInt(searchParams.get('limit') || '20', 10)));
    const skip = (page - 1) * limit;

    if (isMongoActive()) {
      const query: Record<string, any> = { organizationId: org._id };
      if (typeFilter) query.type = typeFilter;
      if (severityFilter) query.severity = severityFilter;
      if (statusFilter) query.deliveryStatus = statusFilter;

      const [total, alerts] = await Promise.all([
        Alert.countDocuments(query),
        Alert.find(query)
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(limit)
          .lean(),
      ]);

      return NextResponse.json({
        success: true,
        data: alerts,
        pagination: {
          page,
          limit,
          total,
          totalPages: Math.ceil(total / limit) || 1,
        },
      });
    }

    // In-memory fallback
    const orgIdStr = org._id.toString();
    const alertsMap = memoryStore.alerts || new Map();
    let allAlerts = Array.from(alertsMap.values()).filter(
      (a: any) => a.organizationId?.toString() === orgIdStr
    );

    if (typeFilter) allAlerts = allAlerts.filter((a) => a.type === typeFilter);
    if (severityFilter) allAlerts = allAlerts.filter((a) => a.severity === severityFilter);
    if (statusFilter) allAlerts = allAlerts.filter((a) => a.deliveryStatus === statusFilter);

    allAlerts.sort(
      (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
    );

    const total = allAlerts.length;
    const paginated = allAlerts.slice(skip, skip + limit);

    return NextResponse.json({
      success: true,
      data: paginated,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit) || 1,
      },
    });
  } catch (error: any) {
    return NextResponse.json(
      { success: false, error: { code: 'ALERTS_FETCH_ERROR', message: error.message } },
      { status: 500 }
    );
  }
}

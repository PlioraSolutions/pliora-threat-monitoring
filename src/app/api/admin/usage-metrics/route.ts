import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth';
import { externalApiTracker } from '@/lib/usage/externalApiTracker';

export async function GET(request: NextRequest) {
  try {
    const auth = await requireAuth(request);
    // Allow OWNER, ADMIN, or global SUPERADMIN
    if (auth.user.role !== 'OWNER' && auth.user.role !== 'ADMIN' && auth.user.globalRole !== 'SUPERADMIN') {
      return NextResponse.json(
        { success: false, error: { code: 'FORBIDDEN', message: 'Admin permissions required' } },
        { status: 403 }
      );
    }

    const metrics = externalApiTracker.getUsageMetrics();
    return NextResponse.json({ success: true, data: metrics });
  } catch (error: any) {
    return NextResponse.json(
      { success: false, error: { code: 'USAGE_METRICS_ERROR', message: error.message } },
      { status: error.status || 500 }
    );
  }
}

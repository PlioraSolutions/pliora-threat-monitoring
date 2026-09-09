import { NextRequest, NextResponse } from 'next/server';
import { metrics } from '@/lib/observability/metrics';
import { getAuthenticatedSession } from '@/lib/auth';

export async function GET(request: NextRequest) {
  // Optional security check: if session exists, verify admin/owner or permit internal telemetry polling
  const session = await getAuthenticatedSession(request);
  if (session && session.user.role === 'VIEWER') {
    return NextResponse.json(
      { success: false, error: { code: 'FORBIDDEN', message: 'Insufficient privileges to view telemetry.' } },
      { status: 403 }
    );
  }

  const snapshot = metrics.getMetricsSnapshot();
  return NextResponse.json({
    success: true,
    data: snapshot,
  });
}

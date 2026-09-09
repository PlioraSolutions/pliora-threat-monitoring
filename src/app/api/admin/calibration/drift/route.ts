import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth';
import { analyzeCalibrationDrift } from '@/lib/calibration/driftAnalysis';
import { applyCalibrationAdjustment, getCalibrationAdjustments } from '@/lib/calibration/adjustment';

export async function GET(request: NextRequest) {
  try {
    const { user, organization: org } = await requireAuth(request);
    const membership = user.organizationMemberships?.find(
      (m: any) => m.organizationId?.toString() === org?._id?.toString()
    );
    const role = membership?.role || user.role || 'VIEWER';
    if (role !== 'OWNER' && role !== 'ADMIN' && user.globalRole !== 'SUPERADMIN') {
      return NextResponse.json(
        { success: false, error: { code: 'FORBIDDEN', message: 'Admin permissions required' } },
        { status: 403 }
      );
    }

    const { searchParams } = new URL(request.url);
    const minSampleSizeStr = searchParams.get('minSampleSize');
    const minSampleSize = minSampleSizeStr ? parseInt(minSampleSizeStr, 10) : undefined;
    const orgId = searchParams.get('organizationId') || undefined;

    const report = await analyzeCalibrationDrift({
      minSampleSize: !isNaN(minSampleSize as number) ? minSampleSize : undefined,
      organizationId: orgId,
    });

    const adjustments = getCalibrationAdjustments(orgId);

    return NextResponse.json({
      success: true,
      data: {
        report,
        adjustments,
      },
    });
  } catch (error: any) {
    return NextResponse.json(
      { success: false, error: { code: 'CALIBRATION_DRIFT_ERROR', message: error.message } },
      { status: error.status || 500 }
    );
  }
}

export async function POST(request: NextRequest) {
  try {
    const { user, organization: org } = await requireAuth(request);
    const membership = user.organizationMemberships?.find(
      (m: any) => m.organizationId?.toString() === org?._id?.toString()
    );
    const role = membership?.role || user.role || 'VIEWER';
    if (role !== 'OWNER' && role !== 'ADMIN' && user.globalRole !== 'SUPERADMIN') {
      return NextResponse.json(
        { success: false, error: { code: 'FORBIDDEN', message: 'Admin permissions required to adjust calibration' } },
        { status: 403 }
      );
    }

    const body = await request.json();
    const { targetType, targetKey, previousValue, adjustedValue, rationale, organizationId } = body;

    const result = await applyCalibrationAdjustment({
      targetType,
      targetKey,
      previousValue,
      adjustedValue,
      rationale,
      actorId: user.id || user._id || 'admin-user',
      organizationId,
    });

    return NextResponse.json({
      success: true,
      data: result,
    });
  } catch (error: any) {
    return NextResponse.json(
      { success: false, error: { code: 'CALIBRATION_ADJUST_ERROR', message: error.message } },
      { status: error.status || 400 }
    );
  }
}

import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth';
import { memoryStore } from '@/lib/store';
import { AuditLog } from '@/models/AuditLog';
import { isMongoActive } from '@/lib/db';

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
    const limit = parseInt(searchParams.get('limit') || '20', 10);

    // Retrieve samples from cached AI explanations
    const samples: any[] = [];
    for (const [key, explanation] of Array.from(memoryStore.aiExplanations.entries())) {
      samples.push({
        id: key,
        ...explanation,
      });
      if (samples.length >= limit) break;
    }

    // Also get recent feedback ratings
    const recentFeedback = (memoryStore.aiFeedback || []).slice(-20);

    return NextResponse.json({
      success: true,
      data: {
        totalCachedExplanations: memoryStore.aiExplanations.size,
        samples,
        recentFeedback,
      },
    });
  } catch (error: any) {
    return NextResponse.json(
      { success: false, error: { code: 'SAMPLE_REVIEW_ERROR', message: error.message } },
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
        { success: false, error: { code: 'FORBIDDEN', message: 'Admin permissions required' } },
        { status: 403 }
      );
    }

    const body = await request.json();
    const { sampleId, status, notes } = body;

    if (!sampleId || (status !== 'APPROVED' && status !== 'NEEDS_REFINEMENT')) {
      return NextResponse.json(
        {
          success: false,
          error: { code: 'INVALID_INPUT', message: 'sampleId and status (APPROVED | NEEDS_REFINEMENT) are required' },
        },
        { status: 400 }
      );
    }

    const reviewEntry = {
      sampleId,
      status,
      reviewerId: user._id?.toString() || user.id || 'admin',
      notes: notes || '',
      reviewedAt: new Date().toISOString(),
    };

    // Log to audit log
    const auditDetails = {
      sampleId,
      status,
      notes,
    };

    if (isMongoActive()) {
      try {
        await AuditLog.create({
          organizationId: org._id,
          actorId: user._id?.toString() || user.id,
          action: 'AI_EXPLANATION_HUMAN_REVIEWED',
          objectType: 'AIExplanation',
          objectId: sampleId,
          result: 'SUCCESS',
          details: auditDetails,
        });
      } catch {
        memoryStore.auditLogs.push({
          actorId: user._id?.toString() || user.id,
          action: 'AI_EXPLANATION_HUMAN_REVIEWED',
          objectType: 'AIExplanation',
          objectId: sampleId,
          result: 'SUCCESS',
          details: auditDetails,
          createdAt: new Date(),
        });
      }
    } else {
      memoryStore.auditLogs.push({
        actorId: user._id?.toString() || user.id,
        action: 'AI_EXPLANATION_HUMAN_REVIEWED',
        objectType: 'AIExplanation',
        objectId: sampleId,
        result: 'SUCCESS',
        details: auditDetails,
        createdAt: new Date(),
      });
    }

    return NextResponse.json({
      success: true,
      data: reviewEntry,
    });
  } catch (error: any) {
    return NextResponse.json(
      { success: false, error: { code: 'SAMPLE_REVIEW_ERROR', message: error.message } },
      { status: error.status || 500 }
    );
  }
}

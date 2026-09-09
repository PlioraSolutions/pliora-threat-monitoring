import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth';
import { memoryStore } from '@/lib/store';
import { AuditLog } from '@/models/AuditLog';
import { isMongoActive } from '@/lib/db';

interface RouteContext {
  params: Promise<{ id: string }> | { id: string };
}

export async function POST(request: NextRequest, context: RouteContext) {
  try {
    const { user, organization: org } = await requireAuth(request);
    const resolvedParams = await Promise.resolve(context.params);
    const findingId = resolvedParams.id;

    const body = await request.json().catch(() => ({}));
    const { rating, comment, modelName } = body;

    if (rating !== 'HELPFUL' && rating !== 'UNHELPFUL') {
      return NextResponse.json(
        {
          success: false,
          error: { code: 'INVALID_RATING', message: 'Rating must be either HELPFUL or UNHELPFUL' },
        },
        { status: 400 }
      );
    }

    const feedbackRecord = {
      id: `fbk-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      findingId,
      organizationId: org._id?.toString(),
      userId: user._id?.toString() || user.id,
      rating,
      comment: comment || '',
      modelName: modelName || 'unknown',
      createdAt: new Date().toISOString(),
    };

    // Store in memoryStore
    if (!memoryStore.aiFeedback) {
      memoryStore.aiFeedback = [];
    }
    memoryStore.aiFeedback.push(feedbackRecord);

    // Audit log
    const auditDetails = {
      findingId,
      rating,
      comment: comment || '',
      modelName,
    };

    if (isMongoActive()) {
      try {
        await AuditLog.create({
          organizationId: org._id,
          actorId: user._id?.toString() || user.id || 'unknown',
          action: 'AI_EXPLANATION_FEEDBACK_RECORDED',
          objectType: 'Finding',
          objectId: findingId,
          result: 'SUCCESS',
          details: auditDetails,
        });
      } catch {
        // Fallback to memory
        memoryStore.auditLogs.push({
          actorId: user._id?.toString() || user.id || 'unknown',
          action: 'AI_EXPLANATION_FEEDBACK_RECORDED',
          objectType: 'Finding',
          objectId: findingId,
          result: 'SUCCESS',
          details: auditDetails,
          createdAt: new Date(),
        });
      }
    } else {
      memoryStore.auditLogs.push({
        actorId: user._id?.toString() || user.id || 'unknown',
        action: 'AI_EXPLANATION_FEEDBACK_RECORDED',
        objectType: 'Finding',
        objectId: findingId,
        result: 'SUCCESS',
        details: auditDetails,
        createdAt: new Date(),
      });
    }

    return NextResponse.json({
      success: true,
      data: feedbackRecord,
    });
  } catch (error: any) {
    return NextResponse.json(
      {
        success: false,
        error: { code: 'FEEDBACK_ERROR', message: error.message || 'Failed to submit feedback' },
      },
      { status: error.status || 500 }
    );
  }
}

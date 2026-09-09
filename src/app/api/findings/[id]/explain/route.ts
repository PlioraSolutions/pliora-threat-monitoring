import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth';
import { explainFinding } from '@/lib/ai/analystService';

interface RouteContext {
  params: Promise<{ id: string }> | { id: string };
}

export async function GET(request: NextRequest, context: RouteContext) {
  try {
    const { user, organization: org } = await requireAuth(request);
    const resolvedParams = await Promise.resolve(context.params);
    const id = resolvedParams.id;

    const url = new URL(request.url);
    const force = url.searchParams.get('force') === 'true';

    const explanation = await explainFinding(id, org._id, {
      forceRegenerate: force,
      actorId: user._id?.toString(),
    });

    if (!explanation) {
      // 404 to prevent cross-tenant indicator enumeration
      return NextResponse.json(
        {
          success: false,
          error: { code: 'NOT_FOUND', message: 'Finding not found.' },
        },
        { status: 404 }
      );
    }

    return NextResponse.json({
      success: true,
      data: explanation,
    });
  } catch (error: any) {
    if (error.message?.includes('Unauthorized')) {
      return NextResponse.json(
        { success: false, error: { code: 'UNAUTHORIZED', message: error.message } },
        { status: 401 }
      );
    }
    return NextResponse.json(
      {
        success: false,
        error: { code: 'AI_EXPLANATION_ERROR', message: error.message || 'Failed to explain finding.' },
      },
      { status: 500 }
    );
  }
}

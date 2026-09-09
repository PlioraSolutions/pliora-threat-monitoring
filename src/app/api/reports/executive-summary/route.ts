import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth';
import { generateExecutiveSummary } from '@/lib/ai/analystService';

export async function GET(request: NextRequest) {
  try {
    const { user, organization: org } = await requireAuth(request);

    const summary = await generateExecutiveSummary(org._id, {
      actorId: user._id?.toString(),
    });

    return NextResponse.json({
      success: true,
      data: summary,
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
        error: { code: 'EXECUTIVE_SUMMARY_ERROR', message: error.message || 'Failed to generate summary.' },
      },
      { status: 500 }
    );
  }
}

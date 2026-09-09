import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth';
import { billingService } from '@/lib/billing/stripe';

export async function POST(request: NextRequest) {
  try {
    const { user, organization: org } = await requireAuth(request, { allowDevDemoFallback: false });

    // Only OWNER and ADMIN can access billing management portal
    const membership = user.organizationMemberships?.find(
      (m: any) => m.organizationId?.toString() === org._id?.toString()
    );
    const role = membership?.role || user.role || 'VIEWER';
    if (role !== 'OWNER' && role !== 'ADMIN') {
      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'FORBIDDEN',
            message: 'Only Organization Owners or Admins are authorized to access the billing portal.',
          },
        },
        { status: 403 }
      );
    }

    const origin = request.nextUrl.origin || 'http://localhost:3000';
    let returnUrl = `${origin}/dashboard/settings`;
    try {
      const body = await request.json();
      if (body.returnUrl) returnUrl = body.returnUrl;
    } catch {}

    const session = await billingService.createCustomerPortalSession({
      organizationId: (org._id || org.id).toString(),
      returnUrl,
    });

    return NextResponse.json({
      success: true,
      data: {
        url: session.url,
      },
    });
  } catch (error: any) {
    const status = error.status || 500;
    return NextResponse.json(
      {
        success: false,
        error: {
          code: error.code || 'PORTAL_CREATION_FAILED',
          message: error.message || 'Failed to initialize customer billing portal session.',
        },
      },
      { status }
    );
  }
}

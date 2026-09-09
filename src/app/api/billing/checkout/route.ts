import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { requireAuth } from '@/lib/auth';
import { billingService } from '@/lib/billing/stripe';

const checkoutSchema = z.object({
  plan: z.enum(['STARTER', 'BUSINESS', 'PRO']),
  successUrl: z.string().url().optional(),
  cancelUrl: z.string().url().optional(),
});

export async function POST(request: NextRequest) {
  try {
    const { user, organization: org } = await requireAuth(request, { allowDevDemoFallback: false });

    // Only OWNER and ADMIN can manage billing subscriptions
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
            message: 'Only Organization Owners or Admins are authorized to initiate subscription upgrades or billing checkout.',
          },
        },
        { status: 403 }
      );
    }

    const body = await request.json();
    const parsed = checkoutSchema.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Invalid plan selected. Must be STARTER, BUSINESS, or PRO.',
            details: parsed.error.format(),
          },
        },
        { status: 400 }
      );
    }

    const origin = request.nextUrl.origin || 'http://localhost:3000';
    const successUrl = parsed.data.successUrl || `${origin}/dashboard/settings?billing_success=true`;
    const cancelUrl = parsed.data.cancelUrl || `${origin}/pricing?billing_canceled=true`;

    const session = await billingService.createCheckoutSession({
      organizationId: (org._id || org.id).toString(),
      plan: parsed.data.plan,
      successUrl,
      cancelUrl,
      customerEmail: user.email,
    });

    return NextResponse.json({
      success: true,
      data: {
        sessionId: session.sessionId,
        url: session.url,
      },
    });
  } catch (error: any) {
    const status = error.status || 500;
    return NextResponse.json(
      {
        success: false,
        error: {
          code: error.code || 'CHECKOUT_CREATION_FAILED',
          message: error.message || 'Failed to initialize subscription checkout session.',
        },
      },
      { status }
    );
  }
}

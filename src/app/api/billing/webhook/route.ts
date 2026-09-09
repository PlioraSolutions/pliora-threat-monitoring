import { NextRequest, NextResponse } from 'next/server';
import { billingService } from '@/lib/billing/stripe';
import { BillingWebhookPayload } from '@/lib/billing/types';
import { errorTracker } from '@/lib/observability/errorTracker';
import { metrics } from '@/lib/observability/metrics';
import { logger } from '@/lib/observability/logger';

export async function POST(request: NextRequest) {
  let event: BillingWebhookPayload | null = null;
  try {
    const signature = request.headers.get('stripe-signature');
    const rawBody = await request.text();

    if (!rawBody) {
      metrics.recordBillingWebhook('EMPTY_BODY', false);
      return NextResponse.json(
        { success: false, error: 'Empty webhook payload' },
        { status: 400 }
      );
    }

    // Cryptographic signature verification
    const isValid = billingService.verifyWebhookSignature(rawBody, signature);
    if (!isValid) {
      metrics.recordBillingWebhook('INVALID_SIGNATURE', false);
      errorTracker.captureBillingWebhookError('SIGNATURE_VERIFICATION_FAILED', undefined, new Error('Invalid Stripe signature'));
      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'INVALID_WEBHOOK_SIGNATURE',
            message: 'Stripe webhook HMAC signature verification failed.',
          },
        },
        { status: 400 }
      );
    }

    event = JSON.parse(rawBody);
    const result = await billingService.handleWebhookEvent(event!);

    metrics.recordBillingWebhook(event!.type, true);
    logger.info(`[BillingWebhook] Successfully processed ${event!.type}`, {
      eventId: event!.id,
      organizationId: result.organizationId,
      action: result.action,
    });

    return NextResponse.json({
      received: true,
      processed: result.processed,
      action: result.action,
      organizationId: result.organizationId,
    });
  } catch (error: any) {
    const eventType = event?.type || 'UNKNOWN_EVENT';
    metrics.recordBillingWebhook(eventType, false);
    errorTracker.captureBillingWebhookError(eventType, event?.id, error);
    logger.error('[BillingWebhook] Processing error', error, { eventType, eventId: event?.id });
    return NextResponse.json(
      {
        success: false,
        error: {
          code: 'WEBHOOK_PROCESSING_FAILED',
          message: error.message || 'Error processing billing webhook event.',
        },
      },
      { status: 500 }
    );
  }
}

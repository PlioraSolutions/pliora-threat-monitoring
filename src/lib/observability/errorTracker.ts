import { redactSensitiveData, logger } from './logger';

export type ErrorCategory =
  | 'SCAN_PIPELINE_FAILURE'
  | 'AI_PROVIDER_FALLBACK'
  | 'ALERT_DELIVERY_FAILURE'
  | 'BILLING_WEBHOOK_ERROR'
  | 'DATABASE_ERROR'
  | 'SECURITY_VIOLATION'
  | 'GENERAL_EXCEPTION';

export interface TrackedErrorEvent {
  id: string;
  category: ErrorCategory;
  timestamp: string;
  message: string;
  stack?: string;
  organizationId?: string;
  context: Record<string, any>;
  environment: string;
}

export interface ErrorTransport {
  send(event: TrackedErrorEvent): Promise<void> | void;
}

/**
 * In-Memory Transport for testing and inspection
 */
export class InMemoryErrorTransport implements ErrorTransport {
  public events: TrackedErrorEvent[] = [];

  send(event: TrackedErrorEvent): void {
    this.events.push(event);
    if (this.events.length > 500) {
      this.events.shift();
    }
  }

  clear(): void {
    this.events = [];
  }
}

/**
 * Production Webhook / External Sentry Transport
 */
export class WebhookErrorTransport implements ErrorTransport {
  private endpointUrl?: string;

  constructor(endpointUrl?: string) {
    this.endpointUrl = endpointUrl || process.env.ERROR_TRACKING_WEBHOOK_URL;
  }

  async send(event: TrackedErrorEvent): Promise<void> {
    if (!this.endpointUrl) return;
    try {
      await fetch(this.endpointUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(event),
      });
    } catch {
      // Never crash the primary process if error reporter fails
    }
  }
}

export class ErrorTracker {
  private transports: ErrorTransport[] = [];
  private inMemoryTransport: InMemoryErrorTransport;

  constructor() {
    this.inMemoryTransport = new InMemoryErrorTransport();
    this.transports.push(this.inMemoryTransport);

    if (process.env.ERROR_TRACKING_WEBHOOK_URL) {
      this.transports.push(new WebhookErrorTransport(process.env.ERROR_TRACKING_WEBHOOK_URL));
    }
  }

  addTransport(transport: ErrorTransport): void {
    this.transports.push(transport);
  }

  private dispatch(
    category: ErrorCategory,
    error: any,
    context: Record<string, any> = {},
    organizationId?: string
  ): TrackedErrorEvent {
    const message = error instanceof Error ? error.message : String(error || 'Unknown error');
    const stack = error instanceof Error ? error.stack : undefined;

    const event: TrackedErrorEvent = {
      id: `err_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`,
      category,
      timestamp: new Date().toISOString(),
      message: redactSensitiveData(message),
      stack: stack ? redactSensitiveData(stack) : undefined,
      organizationId,
      context: redactSensitiveData(context),
      environment: process.env.NODE_ENV || 'development',
    };

    // Log through structured logger
    logger.error(`[ErrorTracker] [${category}] ${event.message}`, error, event.context);

    // Dispatch to transports
    for (const transport of this.transports) {
      try {
        transport.send(event);
      } catch {
        // Silently tolerate transport errors
      }
    }

    return event;
  }

  captureException(error: any, context?: Record<string, any>, organizationId?: string): TrackedErrorEvent {
    return this.dispatch('GENERAL_EXCEPTION', error, context, organizationId);
  }

  captureScanFailure(
    scanId: string,
    targetFqdn: string,
    error: any,
    organizationId?: string,
    extra?: Record<string, any>
  ): TrackedErrorEvent {
    return this.dispatch(
      'SCAN_PIPELINE_FAILURE',
      error,
      { scanId, targetFqdn, ...extra },
      organizationId
    );
  }

  captureAIFallback(
    objectId: string,
    reason: string,
    error?: any,
    organizationId?: string,
    extra?: Record<string, any>
  ): TrackedErrorEvent {
    return this.dispatch(
      'AI_PROVIDER_FALLBACK',
      error || new Error(reason),
      { objectId, reason, ...extra },
      organizationId
    );
  }

  captureAlertDeliveryFailure(
    channel: string,
    destination: string,
    error: any,
    organizationId?: string,
    extra?: Record<string, any>
  ): TrackedErrorEvent {
    return this.dispatch(
      'ALERT_DELIVERY_FAILURE',
      error,
      { channel, destination, ...extra },
      organizationId
    );
  }

  captureBillingWebhookError(
    eventType: string,
    eventId?: string,
    error?: any,
    organizationId?: string,
    extra?: Record<string, any>
  ): TrackedErrorEvent {
    return this.dispatch(
      'BILLING_WEBHOOK_ERROR',
      error || new Error(`Webhook error for ${eventType}`),
      { eventType, eventId, ...extra },
      organizationId
    );
  }

  getRecordedEvents(): TrackedErrorEvent[] {
    return this.inMemoryTransport.events;
  }

  clearForTesting(): void {
    this.inMemoryTransport.clear();
  }
}

export const errorTracker = new ErrorTracker();

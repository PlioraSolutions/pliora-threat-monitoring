/**
 * Centralized Structured Logger for PLIŌRA Threat Monitor
 * Ensures consistent JSON logging in production, readable output in development,
 * and automatic cryptographic redaction of all sensitive secrets and credentials.
 */

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

export interface LogEntry {
  level: LogLevel;
  timestamp: string;
  message: string;
  context?: Record<string, any>;
  error?: {
    name?: string;
    message: string;
    stack?: string;
  };
}

// Sensitive patterns to scrub from all logs and error traces
const SENSITIVE_KEY_PATTERNS = [
  /password/i,
  /secret/i,
  /token/i,
  /apikey/i,
  /authorization/i,
  /cookie/i,
  /credential/i,
  /privatekey/i,
];

const SECRET_VALUE_REGEXES: Array<{ regex: RegExp; replacement: string }> = [
  // Stripe live & test secret keys
  { regex: /sk_(live|test)_[0-9a-zA-Z_]{16,}/g, replacement: 'sk_$1_[REDACTED]' },
  // Stripe webhook secrets
  { regex: /whsec_[0-9a-zA-Z_]{16,}/g, replacement: 'whsec_[REDACTED]' },
  // PLIŌRA customer API keys
  { regex: /plk_live_[0-9a-zA-Z_]{16,}/g, replacement: 'plk_live_[REDACTED]' },
  // Bearer authentication tokens
  { regex: /Bearer\s+([a-zA-Z0-9._\-\+]{15,})/gi, replacement: 'Bearer [REDACTED]' },
  // MongoDB connection strings with password
  { regex: /(mongodb(?:\+srv)?:\/\/[^:]+:)([^@]+)(@.+)/gi, replacement: '$1[REDACTED]$3' },
  // Redis connection string with password
  { regex: /(redis:\/\/[^:]*:)([^@]+)(@.+)/gi, replacement: '$1[REDACTED]$3' },
  // JWT tokens (3 parts)
  { regex: /eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9._-]+/g, replacement: '[JWT_REDACTED]' },
];

/**
 * Deeply scrubs secrets and credentials from any string, object, or array.
 */
export function redactSensitiveData(value: any, depth = 0): any {
  if (depth > 8) return '[MAX_DEPTH_REACHED]';
  if (value === null || value === undefined) return value;

  if (typeof value === 'string') {
    let sanitized = value;
    for (const { regex, replacement } of SECRET_VALUE_REGEXES) {
      sanitized = sanitized.replace(regex, replacement);
    }
    return sanitized;
  }

  if (typeof value === 'number' || typeof value === 'boolean') {
    return value;
  }

  if (Array.isArray(value)) {
    return value.map((item) => redactSensitiveData(item, depth + 1));
  }

  if (value instanceof Error) {
    let sanitizedStack = value.stack || '';
    for (const { regex, replacement } of SECRET_VALUE_REGEXES) {
      sanitizedStack = sanitizedStack.replace(regex, replacement);
    }
    return {
      name: value.name,
      message: redactSensitiveData(value.message, depth + 1),
      stack: sanitizedStack,
    };
  }

  if (typeof value === 'object') {
    const sanitizedObj: Record<string, any> = {};
    for (const [key, val] of Object.entries(value)) {
      const isSensitiveKey = SENSITIVE_KEY_PATTERNS.some((pattern) => pattern.test(key));
      if (isSensitiveKey && typeof val === 'string' && val.length > 0) {
        sanitizedObj[key] = '[REDACTED]';
      } else {
        sanitizedObj[key] = redactSensitiveData(val, depth + 1);
      }
    }
    return sanitizedObj;
  }

  return String(value);
}

export class StructuredLogger {
  private inMemoryLogBuffer: LogEntry[] = [];
  private maxBufferSize = 200;

  private emit(level: LogLevel, message: string, context?: Record<string, any>, error?: any): void {
    const entry: LogEntry = {
      level,
      timestamp: new Date().toISOString(),
      message: redactSensitiveData(message),
      context: context ? redactSensitiveData(context) : undefined,
      error: error ? redactSensitiveData(error) : undefined,
    };

    // Buffer for inspection/testing
    this.inMemoryLogBuffer.push(entry);
    if (this.inMemoryLogBuffer.length > this.maxBufferSize) {
      this.inMemoryLogBuffer.shift();
    }

    const isProd = process.env.NODE_ENV === 'production';
    if (isProd) {
      const jsonLine = JSON.stringify(entry);
      if (level === 'error') {
        console.error(jsonLine);
      } else if (level === 'warn') {
        console.warn(jsonLine);
      } else {
        console.log(jsonLine);
      }
    } else {
      // In dev/test, output clean formatted line
      const prefix = `[${entry.timestamp}] [${level.toUpperCase()}]`;
      const contextStr = entry.context ? ` | context: ${JSON.stringify(entry.context)}` : '';
      const errorStr = entry.error ? ` | error: ${entry.error.message}` : '';

      if (level === 'error') {
        console.error(`${prefix} ${entry.message}${contextStr}${errorStr}`);
      } else if (level === 'warn') {
        console.warn(`${prefix} ${entry.message}${contextStr}`);
      } else {
        console.log(`${prefix} ${entry.message}${contextStr}`);
      }
    }
  }

  info(message: string, context?: Record<string, any>): void {
    this.emit('info', message, context);
  }

  warn(message: string, context?: Record<string, any>): void {
    this.emit('warn', message, context);
  }

  error(message: string, error?: any, context?: Record<string, any>): void {
    this.emit('error', message, context, error);
  }

  debug(message: string, context?: Record<string, any>): void {
    this.emit('debug', message, context);
  }

  getRecentLogs(): LogEntry[] {
    return [...this.inMemoryLogBuffer];
  }

  clearLogsForTesting(): void {
    this.inMemoryLogBuffer = [];
  }
}

export const logger = new StructuredLogger();

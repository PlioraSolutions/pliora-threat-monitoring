import { env } from '@/lib/env';

export interface CompletionOptions {
  systemPrompt: string;
  userPrompt: string;
  jsonSchema?: Record<string, any>;
  temperature?: number;
  timeoutMs?: number;
}

export interface ILLMProvider {
  readonly providerName: string;
  generateStructuredCompletion<T>(options: CompletionOptions): Promise<T>;
}

/**
 * Deterministic mock provider for tests and zero-config development.
 * Provides schema-valid, contextual responses without making external network calls.
 */
export class MockLLMProvider implements ILLMProvider {
  readonly providerName = 'mock';

  private customHandler?: (options: CompletionOptions) => Promise<any>;

  constructor(customHandler?: (options: CompletionOptions) => Promise<any>) {
    this.customHandler = customHandler;
  }

  setHandler(handler: (options: CompletionOptions) => Promise<any>) {
    this.customHandler = handler;
  }

  resetHandler() {
    this.customHandler = undefined;
  }

  async generateStructuredCompletion<T>(options: CompletionOptions): Promise<T> {
    if (this.customHandler) {
      return this.customHandler(options);
    }

    const { userPrompt, timeoutMs = 5000 } = options;

    // Simulate small latency
    await new Promise((resolve) => setTimeout(resolve, Math.min(20, timeoutMs)));

    // Contextual extraction from user prompt
    if (userPrompt.includes('executiveSummary') || userPrompt.includes('Executive Summary')) {
      const summary: any = {
        executiveSummary:
          'Your overall external attack surface shows several high-priority security concerns that require proactive mitigation to protect corporate assets and customer trust.',
        overallPosture: 'MODERATE',
        keyRisks: [
          'Critical exposure on production endpoints — potential data leakage or communication interception across unencrypted channels.',
          'Missing HTTP security headers (HSTS, CSP) leave users vulnerable to downgrade and injection attacks.',
          'Active look-alike domains detected — elevated phishing and brand impersonation risk.',
        ],
        priorityActions: [
          'Deploy HSTS and Content-Security-Policy headers across all production endpoints.',
          'Renew or replace any outdated TLS certificates.',
          'Monitor typosquat brand permutations for active mail or phishing infrastructure.',
        ],
        totalConfirmedFindings: 2,
        totalHighThreats: 1,
      };
      return summary as T;
    }

    // Default finding / threat structured output
    let code = 'MISSING_HSTS_HEADER';
    if (userPrompt.includes('TLS_WEAK_PROTOCOL')) code = 'TLS_WEAK_PROTOCOL';
    else if (userPrompt.includes('TLS_CERT_EXPIRED')) code = 'TLS_CERT_EXPIRED';
    else if (userPrompt.includes('TYPOSQUAT_DOMAIN_DETECTED') || userPrompt.includes('TYPOSQUAT')) {
      code = 'TYPOSQUAT_DOMAIN_DETECTED';
    }

    let explanation =
      'The server is not currently enforcing HTTP Strict Transport Security (HSTS), allowing potential downgrade attacks.';
    let businessImpact =
      'Users connecting to this service over insecure networks could have their traffic intercepted or redirected to malicious clones.';
    let remediationSteps = [
      'Add the Strict-Transport-Security response header across all production HTTPS endpoints.',
      'Set the max-age directive to at least 31536000 seconds (1 year) to enforce HTTPS persistence.',
    ];
    let citedEvidenceFields = ['findingCode', 'severity', 'description'];

    if (code === 'TLS_WEAK_PROTOCOL') {
      explanation = 'The web server supports deprecated TLS 1.0 or 1.1 cryptographic protocols.';
      businessImpact =
        'Legacy cryptographic protocols have known mathematical vulnerabilities that permit session hijacking and credential theft.';
      remediationSteps = [
        'Disable legacy TLS 1.0 and TLS 1.1 in your web server or load balancer configuration.',
        'Enforce TLS 1.2 as the minimum supported protocol version, and enable TLS 1.3 for optimal performance and forward secrecy.',
      ];
      citedEvidenceFields = ['findingCode', 'severity', 'details'];
    } else if (code === 'TYPOSQUAT_DOMAIN_DETECTED') {
      explanation =
        'A suspicious look-alike domain closely matching your brand name was discovered on public DNS infrastructure.';
      businessImpact =
        'Attackers may use this deceptive domain to send phishing emails to your customers or host fraudulent credential-harvesting portals.';
      remediationSteps = [
        'Monitor the suspicious look-alike domain continuously for infrastructure changes (DNS records, MX records, SSL certs).',
        'Evaluate defensive registration or dispute proceedings (e.g. UDRP or registrar abuse complaint) if brand infringement is evident.',
      ];
      citedEvidenceFields = ['indicator', 'source', 'corroborationScore'];
    }

    const result: any = {
      explanation,
      businessImpact,
      remediationSteps,
      citedEvidenceFields,
    };

    return result as T;
  }
}

/**
 * Google Gemini Provider using native HTTP and JSON mode.
 */
export class GeminiProvider implements ILLMProvider {
  readonly providerName = 'gemini';
  private apiKey: string;
  private model: string;

  constructor(apiKey: string, model = 'gemini-1.5-flash') {
    this.apiKey = apiKey;
    this.model = model;
  }

  async generateStructuredCompletion<T>(options: CompletionOptions): Promise<T> {
    const { systemPrompt, userPrompt, temperature = 0.2, timeoutMs = env.AI_REQUEST_TIMEOUT_MS } = options;
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${this.model}:generateContent?key=${this.apiKey}`;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        signal: controller.signal,
        body: JSON.stringify({
          systemInstruction: {
            parts: [{ text: systemPrompt }],
          },
          contents: [
            {
              role: 'user',
              parts: [{ text: userPrompt }],
            },
          ],
          generationConfig: {
            temperature,
            responseMimeType: 'application/json',
          },
        }),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Gemini API error (HTTP ${response.status}): ${errorText}`);
      }

      const data = await response.json();
      const rawText = data?.candidates?.[0]?.content?.parts?.[0]?.text;
      if (!rawText) {
        throw new Error('Gemini API returned empty completion text');
      }

      return JSON.parse(rawText) as T;
    } finally {
      clearTimeout(timeoutId);
    }
  }
}

/**
 * OpenAI Provider using native HTTP and json_object response format.
 */
export class OpenAIProvider implements ILLMProvider {
  readonly providerName = 'openai';
  private apiKey: string;
  private model: string;

  constructor(apiKey: string, model = 'gpt-4o-mini') {
    this.apiKey = apiKey;
    this.model = model;
  }

  async generateStructuredCompletion<T>(options: CompletionOptions): Promise<T> {
    const { systemPrompt, userPrompt, temperature = 0.2, timeoutMs = env.AI_REQUEST_TIMEOUT_MS } = options;
    const url = 'https://api.openai.com/v1/chat/completions';

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${this.apiKey}`,
        },
        signal: controller.signal,
        body: JSON.stringify({
          model: this.model,
          temperature,
          response_format: { type: 'json_object' },
          messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: userPrompt },
          ],
        }),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`OpenAI API error (HTTP ${response.status}): ${errorText}`);
      }

      const data = await response.json();
      const rawContent = data?.choices?.[0]?.message?.content;
      if (!rawContent) {
        throw new Error('OpenAI API returned empty response content');
      }

      return JSON.parse(rawContent) as T;
    } finally {
      clearTimeout(timeoutId);
    }
  }
}

// Global mock instance to permit test overrides
let activeMockProvider: MockLLMProvider | null = null;

export function getMockProvider(): MockLLMProvider {
  if (!activeMockProvider) {
    activeMockProvider = new MockLLMProvider();
  }
  return activeMockProvider;
}

/**
 * MultiProviderChain executes an ordered list of LLM providers:
 * Primary -> Secondary -> ...
 * If the primary encounters an error or timeout, the secondary is attempted automatically.
 */
export class MultiProviderChain implements ILLMProvider {
  readonly providerName: string;
  private providers: ILLMProvider[];
  private lastServedProvider?: string;

  constructor(providers: ILLMProvider[]) {
    if (!providers || providers.length === 0) {
      throw new Error('MultiProviderChain requires at least one provider');
    }
    this.providers = providers;
    this.providerName = providers.map((p) => p.providerName).join('->');
  }

  getLastServedProvider(): string | undefined {
    return this.lastServedProvider;
  }

  async generateStructuredCompletion<T>(options: CompletionOptions): Promise<T> {
    const errors: Array<{ provider: string; error: string }> = [];

    for (let i = 0; i < this.providers.length; i++) {
      const currentProvider = this.providers[i];
      try {
        const result = await currentProvider.generateStructuredCompletion<T>(options);
        this.lastServedProvider = currentProvider.providerName;
        return result;
      } catch (err: any) {
        errors.push({ provider: currentProvider.providerName, error: err.message });
      }
    }

    throw new Error(
      `MultiProviderChain exhausted all providers: ${errors
        .map((e) => `[${e.provider}: ${e.error}]`)
        .join(', ')}`
    );
  }
}

export function createMultiProviderChain(providers: ILLMProvider[]): MultiProviderChain {
  return new MultiProviderChain(providers);
}

/**
 * Provider factory: selects configured provider chain with fallback.
 */
export function getLLMProvider(overrideProvider?: string): ILLMProvider {
  const chosen = overrideProvider || env.AI_PROVIDER;

  if (chosen === 'mock' || env.NODE_ENV === 'test') {
    return getMockProvider();
  }

  const chain: ILLMProvider[] = [];

  if (chosen === 'gemini') {
    if (env.GEMINI_API_KEY) {
      chain.push(new GeminiProvider(env.GEMINI_API_KEY, env.AI_MODEL));
    }
    if (env.OPENAI_API_KEY) {
      chain.push(new OpenAIProvider(env.OPENAI_API_KEY, 'gpt-4o-mini'));
    }
  } else if (chosen === 'openai') {
    if (env.OPENAI_API_KEY) {
      chain.push(new OpenAIProvider(env.OPENAI_API_KEY, env.AI_MODEL.startsWith('gpt') ? env.AI_MODEL : 'gpt-4o-mini'));
    }
    if (env.GEMINI_API_KEY) {
      chain.push(new GeminiProvider(env.GEMINI_API_KEY, 'gemini-1.5-flash'));
    }
  }

  if (chain.length > 1) {
    return new MultiProviderChain(chain);
  } else if (chain.length === 1) {
    return chain[0];
  }

  // Safe fallback if keys are missing
  return getMockProvider();
}

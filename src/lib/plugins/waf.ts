export interface WafDetectionResult {
  isWafDetected: boolean;
  vendor?: string;
  signature?: string;
}

/**
 * Inspects HTTP response status, headers, and body content for WAF or anti-bot challenge signatures.
 * When detected, prevents recording a false-clean pass and tags check as INCONCLUSIVE.
 */
export function detectWafOrBotBlock(
  statusCode: number,
  headers: Headers | Record<string, string | null>,
  bodyText: string
): WafDetectionResult {
  const getHeader = (name: string): string => {
    if (headers instanceof Headers) {
      return headers.get(name) || '';
    }
    return (headers as Record<string, string | null>)[name.toLowerCase()] || '';
  };

  const serverHeader = getHeader('server').toLowerCase();
  const cfRay = getHeader('cf-ray');
  const cfMitigated = getHeader('cf-mitigated');
  const cfChlBypass = getHeader('cf-chl-bypass');
  const amzWaf = getHeader('x-amzn-waf-action');
  const sucuriBlock = getHeader('x-sucuri-block');
  const dataDome = getHeader('x-datadome');
  const incapsula = getHeader('x-iinfo') || getHeader('x-cdn');

  const lowerBody = bodyText.toLowerCase();

  // Cloudflare Challenge / Turnstile / 1020 Block
  if (
    cfMitigated ||
    cfChlBypass ||
    lowerBody.includes('attention required! | cloudflare') ||
    lowerBody.includes('cf-browser-verification') ||
    lowerBody.includes('challenge-running') ||
    lowerBody.includes('checking your browser before accessing') ||
    lowerBody.includes('<form id="challenge-form">') ||
    (serverHeader.includes('cloudflare') && [403, 503].includes(statusCode) && cfRay)
  ) {
    return {
      isWafDetected: true,
      vendor: 'Cloudflare WAF / Turnstile',
      signature: cfMitigated ? 'cf-mitigated header' : 'Cloudflare browser challenge page',
    };
  }

  // AWS WAF
  if (
    amzWaf ||
    lowerBody.includes('awswaf') ||
    (statusCode === 403 && lowerBody.includes('request blocked by aws waf'))
  ) {
    return {
      isWafDetected: true,
      vendor: 'AWS WAF',
      signature: amzWaf ? 'x-amzn-waf-action header' : 'AWS WAF block page',
    };
  }

  // Imperva / Incapsula
  if (
    incapsula.toLowerCase().includes('incapsula') ||
    lowerBody.includes('_incapsula_resource') ||
    lowerBody.includes('incident id') && lowerBody.includes('incapsula')
  ) {
    return {
      isWafDetected: true,
      vendor: 'Imperva Incapsula WAF',
      signature: 'Incapsula block or challenge resource',
    };
  }

  // Sucuri Firewall
  if (sucuriBlock || lowerBody.includes('access denied - sucuri website firewall')) {
    return {
      isWafDetected: true,
      vendor: 'Sucuri CloudProxy WAF',
      signature: 'Sucuri firewall access denial page',
    };
  }

  // DataDome
  if (dataDome || lowerBody.includes('datadome.co')) {
    return {
      isWafDetected: true,
      vendor: 'DataDome Bot Protection',
      signature: 'DataDome challenge script or header',
    };
  }

  // Akamai
  if (
    getHeader('x-akamai-transformed') &&
    statusCode === 403 &&
    (lowerBody.includes('access denied') || lowerBody.includes('reference #'))
  ) {
    return {
      isWafDetected: true,
      vendor: 'Akamai Edge WAF',
      signature: 'Akamai access denied reference',
    };
  }

  // Generic 403 CAPTCHA or Anti-Bot interstitial
  if (
    [403, 429].includes(statusCode) &&
    (lowerBody.includes('verify you are human') ||
      lowerBody.includes('enable javascript and cookies') ||
      lowerBody.includes('please complete the security check to access'))
  ) {
    return {
      isWafDetected: true,
      vendor: 'Generic Bot Protection / Interstitial',
      signature: 'Human verification / anti-bot challenge interstitial',
    };
  }

  return { isWafDetected: false };
}

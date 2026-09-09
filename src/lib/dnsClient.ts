import dns from 'dns';

export const resilientResolver = new dns.promises.Resolver();
try {
  resilientResolver.setServers(['8.8.8.8', '1.1.1.1', '8.8.4.4', '1.0.0.1']);
} catch {
  // Use default OS resolvers if custom server list fails
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      const err: any = new Error('DNS query timeout');
      err.code = 'ETIMEOUT';
      reject(err);
    }, ms);
    promise
      .then((res) => {
        clearTimeout(timer);
        resolve(res);
      })
      .catch((err) => {
        clearTimeout(timer);
        reject(err);
      });
  });
}

/**
 * Executes a DNS query with automatic fallback to high-reliability public resolvers
 * if the local operating system or network resolver returns ECONNREFUSED, ETIMEOUT, or ESERVFAIL.
 */
async function withResilientFallback<T>(
  primaryFn: () => Promise<T>,
  fallbackFn: () => Promise<T>
): Promise<T> {
  try {
    return await withTimeout(primaryFn(), 800);
  } catch (err: any) {
    const isNetworkGlitch =
      err &&
      (err.code === 'ECONNREFUSED' ||
        err.code === 'ETIMEOUT' ||
        err.code === 'ESERVFAIL' ||
        err.code === 'EREFUSED');

    if (isNetworkGlitch) {
      return await withTimeout(fallbackFn(), 1500);
    }
    throw err;
  }
}

export const dnsClient = {
  resilientResolveTxt: async (hostname: string): Promise<string[][]> => {
    return withResilientFallback(
      () => dns.promises.resolveTxt(hostname),
      () => resilientResolver.resolveTxt(hostname)
    );
  },
  resilientResolveNs: async (hostname: string): Promise<string[]> => {
    return withResilientFallback(
      () => dns.promises.resolveNs(hostname),
      () => resilientResolver.resolveNs(hostname)
    );
  },
  resilientResolveCaa: async (hostname: string): Promise<any[]> => {
    return withResilientFallback(
      () => dns.promises.resolveCaa(hostname),
      () => resilientResolver.resolveCaa(hostname)
    );
  },
  resilientResolveCname: async (hostname: string): Promise<string[]> => {
    return withResilientFallback(
      () => dns.promises.resolveCname(hostname),
      () => resilientResolver.resolveCname(hostname)
    );
  },
  resilientResolveSoa: async (hostname: string): Promise<any> => {
    return withResilientFallback(
      () => dns.promises.resolveSoa(hostname),
      () => resilientResolver.resolveSoa(hostname)
    );
  },
  resilientLookup: async (hostname: string): Promise<{ address: string; family: number }> => {
    return withResilientFallback(
      () => dns.promises.lookup(hostname),
      async () => {
        const addresses = await resilientResolver.resolve4(hostname);
        return { address: addresses[0], family: 4 };
      }
    );
  },
};

export async function resilientResolveTxt(hostname: string): Promise<string[][]> {
  return dnsClient.resilientResolveTxt(hostname);
}

export async function resilientResolveNs(hostname: string): Promise<string[]> {
  return dnsClient.resilientResolveNs(hostname);
}

export async function resilientResolveCaa(hostname: string): Promise<any[]> {
  return dnsClient.resilientResolveCaa(hostname);
}

export async function resilientResolveCname(hostname: string): Promise<string[]> {
  return dnsClient.resilientResolveCname(hostname);
}

export async function resilientResolveSoa(hostname: string): Promise<any> {
  return dnsClient.resilientResolveSoa(hostname);
}

export async function resilientLookup(hostname: string): Promise<{ address: string; family: number }> {
  return dnsClient.resilientLookup(hostname);
}

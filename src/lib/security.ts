import dns from 'dns/promises';
import net from 'net';
import tls from 'tls';

export interface PinnedTarget {
  hostname: string;
  pinnedIp: string;
  allIps: string[];
}

/**
 * Checks whether an IP address belongs to internal, loopback, private or cloud metadata ranges.
 * Implements R&D Report §9.1 SSRF & Worker Sandboxing requirement.
 */
export function isSafeExternalIp(ip: string): boolean {
  if (!net.isIP(ip)) {
    return false;
  }

  // IPv4 checks
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    const [p0, p1, p2, p3] = parts;

    // 0.0.0.0/8 (Current network / "this" network)
    if (p0 === 0) return false;

    // 127.0.0.0/8 (Loopback)
    if (p0 === 127) return false;

    // 10.0.0.0/8 (Private RFC1918)
    if (p0 === 10) return false;

    // 172.16.0.0/12 (Private RFC1918: 172.16.0.0 - 172.31.255.255)
    if (p0 === 172 && p1 >= 16 && p1 <= 31) return false;

    // 192.168.0.0/16 (Private RFC1918)
    if (p0 === 192 && p1 === 168) return false;

    // 169.254.0.0/16 (Link-Local & Cloud Instance Metadata, e.g., 169.254.169.254)
    if (p0 === 169 && p1 === 254) return false;

    // 100.64.0.0/10 (Carrier-grade NAT RFC6598: 100.64.0.0 - 100.127.255.255)
    if (p0 === 100 && p1 >= 64 && p1 <= 127) return false;

    // 192.0.0.0/24 (IETF Protocol Assignments)
    if (p0 === 192 && p1 === 0 && p2 === 0) return false;

    // 192.0.2.0/24 (TEST-NET-1 documentation)
    if (p0 === 192 && p1 === 0 && p2 === 2) return false;

    // 198.18.0.0/15 (Network benchmark tests: 198.18.0.0 - 198.19.255.255)
    if (p0 === 198 && (p1 === 18 || p1 === 19)) return false;

    // 198.51.100.0/24 (TEST-NET-2 documentation)
    if (p0 === 198 && p1 === 51 && p2 === 100) return false;

    // 203.0.113.0/24 (TEST-NET-3 documentation)
    if (p0 === 203 && p1 === 0 && p2 === 113) return false;

    // 224.0.0.0/4 (Multicast: 224.0.0.0 - 239.255.255.255)
    if (p0 >= 224 && p0 <= 239) return false;

    // 240.0.0.0/4 (Reserved / Future Use: 240.0.0.0 - 255.255.255.254)
    if (p0 >= 240) return false;

    return true;
  }

  // IPv6 checks
  if (net.isIPv6(ip)) {
    const normalized = ip.toLowerCase();

    // Loopback (::1)
    if (normalized === '::1' || normalized === '0000:0000:0000:0000:0000:0000:0000:0001') return false;

    // Unspecified (::)
    if (normalized === '::' || /^0(:0){1,7}$/.test(normalized)) return false;

    // IPv6 link-local (fe80::/10 -> fe80:: to febf::)
    if (/^fe[89ab]/i.test(normalized)) return false;

    // IPv6 unique local (fc00::/7 -> fc00:: to fdff::)
    if (/^f[cd]/i.test(normalized)) return false;

    // IPv6 multicast (ff00::/8)
    if (normalized.startsWith('ff')) return false;

    // IPv6 documentation (2001:db8::/32)
    if (normalized.startsWith('2001:db8:') || normalized.startsWith('2001:0db8:')) return false;

    // IPv6 discard-only (100::/64)
    if (normalized.startsWith('100::') || normalized.startsWith('0100::')) return false;

    // IPv6 ORCHIDv2 (2001:10::/28 to 2001:2f::)
    if (/^2001:(00)?1[0-9a-f]:/i.test(normalized)) return false;

    // IPv4-mapped IPv6 (::ffff:127.0.0.1 or ::ffff:7f00:1)
    if (normalized.startsWith('::ffff:')) {
      const remaining = normalized.replace('::ffff:', '');
      if (net.isIPv4(remaining)) {
        return isSafeExternalIp(remaining);
      }
      // If formatted as hex e.g. ::ffff:7f00:0001
      const hexParts = remaining.split(':');
      if (hexParts.length === 2) {
        const v4_1 = parseInt(hexParts[0].slice(0, 2), 16);
        const v4_2 = parseInt(hexParts[0].slice(2, 4), 16);
        const v4_3 = parseInt(hexParts[1].slice(0, 2), 16);
        const v4_4 = parseInt(hexParts[1].slice(2, 4), 16);
        return isSafeExternalIp(`${v4_1}.${v4_2}.${v4_3}.${v4_4}`);
      }
      return false;
    }

    // NAT64 prefix (64:ff9b::/96)
    if (normalized.startsWith('64:ff9b::')) {
      const remaining = normalized.replace('64:ff9b::', '');
      if (net.isIPv4(remaining)) {
        return isSafeExternalIp(remaining);
      }
      return false;
    }

    return true;
  }

  return false;
}

/**
 * Resolves a hostname, pins its verified safe IP address, and guards against TOCTOU DNS rebinding.
 */
export async function resolveAndPinTarget(hostname: string): Promise<PinnedTarget> {
  let hostPart = hostname
    .replace(/^https?:\/\//i, '')
    .split('/')[0]
    .split('?')[0]
    .split('#')[0]
    .trim();

  // Strip brackets if bracketed IPv6: [fe80::1] or [fe80::1]:8080
  if (hostPart.startsWith('[')) {
    const closingBracket = hostPart.indexOf(']');
    if (closingBracket !== -1) {
      hostPart = hostPart.slice(1, closingBracket);
    }
  } else if (!net.isIP(hostPart)) {
    // If it is not a valid IP and contains exactly one colon, it's host:port (IPv4 or domain)
    const colonCount = (hostPart.match(/:/g) || []).length;
    if (colonCount === 1) {
      hostPart = hostPart.split(':')[0];
    }
  }

  const cleanHost = hostPart.toLowerCase().replace(/\.+$/, '');

  if (!cleanHost) {
    throw new Error('SSRF Blocked: Target hostname cannot be empty.');
  }

  // Reject loopback and internal domain suffixes
  const blockedSuffixes = [
    'localhost',
    '.local',
    '.internal',
    '.intranet',
    '.lan',
    '.home',
    '.corp',
    '.arpa',
    '.onion',
    '.test',
    '.invalid',
    '.example',
  ];

  if (
    cleanHost === 'localhost' ||
    blockedSuffixes.some((s) => (s.startsWith('.') ? cleanHost.endsWith(s) : cleanHost === s))
  ) {
    throw new Error(`SSRF Blocked: Hostname "${cleanHost}" targets private or internal domain namespaces.`);
  }

  // If already an IP address, validate immediately
  if (net.isIP(cleanHost)) {
    if (!isSafeExternalIp(cleanHost)) {
      throw new Error(`SSRF Blocked: Destination IP "${cleanHost}" is in a private, reserved or metadata range.`);
    }
    return {
      hostname: cleanHost,
      pinnedIp: cleanHost,
      allIps: [cleanHost],
    };
  }

  // Resolve target via DNS (handling both IPv4 and IPv6)
  let resolvedAddresses: string[] = [];

  try {
    const lookupRes = await dns.lookup(cleanHost, { all: true });
    resolvedAddresses = lookupRes.map((r) => r.address);
  } catch (err: any) {
    // Fallback to resolve4 and resolve6
    const [v4, v6] = await Promise.allSettled([
      dns.resolve4(cleanHost),
      dns.resolve6(cleanHost),
    ]);

    if (v4.status === 'fulfilled') resolvedAddresses.push(...v4.value);
    if (v6.status === 'fulfilled') resolvedAddresses.push(...v6.value);
  }

  // De-duplicate
  resolvedAddresses = Array.from(new Set(resolvedAddresses));

  if (!resolvedAddresses || resolvedAddresses.length === 0) {
    throw new Error(`DNS Resolution failed: No A or AAAA records found for host "${cleanHost}".`);
  }

  // Crucial DNS Rebinding Defense:
  // If even ONE resolved IP points to private/internal/metadata space, REJECT the entire request.
  for (const address of resolvedAddresses) {
    if (!isSafeExternalIp(address)) {
      throw new Error(`SSRF Blocked: Hostname "${cleanHost}" resolved to restricted IP "${address}". Request rejected.`);
    }
  }

  return {
    hostname: cleanHost,
    pinnedIp: resolvedAddresses[0],
    allIps: resolvedAddresses,
  };
}

/**
 * Resolves a hostname and asserts all resolved IP addresses are safe external destinations.
 * Maintained for backwards compatibility with scanner workers and verification routines.
 */
export async function assertSafeTargetHostname(hostname: string): Promise<string[]> {
  const target = await resolveAndPinTarget(hostname);
  return target.allIps;
}

export interface SafeFetchOptions extends RequestInit {
  maxRedirects?: number;
  timeoutMs?: number;
}

/**
 * Safe fetch wrapper that enforces SSRF defense on every hop and redirect.
 * Blocks redirects to 127.0.0.1, AWS/GCP metadata endpoints (169.254.169.254), or internal RFC1918 subnets.
 */
export async function safeFetch(
  targetUrl: string,
  options: SafeFetchOptions = {}
): Promise<Response> {
  const { maxRedirects = 5, timeoutMs = 8000, ...fetchInit } = options;

  let currentUrl = targetUrl;
  let redirectsRemaining = maxRedirects;

  while (true) {
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(currentUrl);
    } catch {
      throw new Error(`SSRF Blocked: Invalid URL "${currentUrl}".`);
    }

    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      throw new Error(`SSRF Blocked: Unsupported protocol "${parsedUrl.protocol}". Only HTTP and HTTPS are permitted.`);
    }

    // Validate hostname on each hop against SSRF rules
    await resolveAndPinTarget(parsedUrl.hostname);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);

    let response: Response;
    try {
      response = await fetch(currentUrl, {
        ...fetchInit,
        redirect: 'manual', // Intercept redirects for verification
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timeout);
    }

    // Check if response is a redirect
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get('location');
      if (!location) {
        return response; // Redirect without Location header, return as-is
      }

      if (redirectsRemaining <= 0) {
        throw new Error(`SSRF Blocked: Maximum redirect limit (${maxRedirects}) exceeded.`);
      }

      redirectsRemaining--;

      // Resolve relative redirects against current URL
      const nextUrl = new URL(location, currentUrl).toString();
      currentUrl = nextUrl;
      continue;
    }

    return response;
  }
}

export interface SafeTlsResult {
  authorized: boolean;
  authorizationError?: string;
  protocol: string | null;
  cipher: { name: string; version: string } | null;
  peerCertificate: Record<string, any> | null;
  daysRemaining: number;
  isExpired: boolean;
  isSelfSigned: boolean;
  subjectAltNames: string[];
  commonName: string;
  pinnedIp: string;
}

/**
 * Performs a secure TLS handshake against a target hostname through the pinned SSRF-safe IP.
 * Captures protocol version, cipher suite, certificate validity, self-signed flag, and SANs.
 */
export async function safeTlsHandshake(
  hostname: string,
  port: number = 443,
  options: { timeoutMs?: number } = {}
): Promise<SafeTlsResult> {
  const { timeoutMs = 8000 } = options;

  // 1. Enforce strict SSRF check and pin target IP
  const pinned = await resolveAndPinTarget(hostname);

  return new Promise((resolve, reject) => {
    let socket: tls.TLSSocket | null = null;
    let timer: NodeJS.Timeout | null = null;
    let resolved = false;

    const cleanup = () => {
      if (timer) clearTimeout(timer);
      if (socket && !socket.destroyed) {
        socket.destroy();
      }
    };

    timer = setTimeout(() => {
      if (!resolved) {
        resolved = true;
        cleanup();
        reject(new Error(`TLS handshake timeout after ${timeoutMs}ms for ${hostname}`));
      }
    }, timeoutMs);

    try {
      socket = tls.connect(
        {
          host: pinned.pinnedIp,
          port,
          servername: pinned.hostname,
          rejectUnauthorized: false, // capture cert details even if untrusted/expired
        },
        () => {
          if (resolved) return;
          resolved = true;

          try {
            const protocol = socket?.getProtocol() || null;
            const cipher = socket?.getCipher() || null;
            const cert = socket?.getPeerCertificate(true);
            const authorized = socket?.authorized ?? false;
            const authorizationError = socket?.authorizationError ? String(socket.authorizationError) : undefined;

            let isExpired = false;
            let daysRemaining = 9999;
            let isSelfSigned = false;
            let commonName = '';
            const subjectAltNames: string[] = [];

            if (cert && Object.keys(cert).length > 0) {
              const validTo = new Date(cert.valid_to);
              const now = new Date();
              const diffMs = validTo.getTime() - now.getTime();
              daysRemaining = Math.floor(diffMs / (1000 * 60 * 60 * 24));
              isExpired = daysRemaining < 0;

              const rawCn = cert.subject?.CN;
              commonName = Array.isArray(rawCn) ? String(rawCn[0]) : String(rawCn || '');
              if (cert.subjectaltname) {
                const parts = cert.subjectaltname.split(',').map((s) => s.trim());
                for (const part of parts) {
                  if (part.startsWith('DNS:')) {
                    subjectAltNames.push(part.replace(/^DNS:/i, ''));
                  } else if (part.startsWith('IP Address:')) {
                    subjectAltNames.push(part.replace(/^IP Address:/i, ''));
                  } else {
                    subjectAltNames.push(part);
                  }
                }
              }

              // Self-signed check: subject matches issuer or issuer certificate is itself
              if (
                cert.subject &&
                cert.issuer &&
                (cert.subject.CN === cert.issuer.CN ||
                  (cert.fingerprint && (cert as any).issuerCertificate?.fingerprint === cert.fingerprint))
              ) {
                isSelfSigned = true;
              }
            }

            cleanup();

            resolve({
              authorized,
              authorizationError,
              protocol,
              cipher,
              peerCertificate: cert && Object.keys(cert).length > 0 ? {
                subject: cert.subject,
                issuer: cert.issuer,
                valid_from: cert.valid_from,
                valid_to: cert.valid_to,
                subjectaltname: cert.subjectaltname,
                fingerprint: cert.fingerprint,
                serialNumber: cert.serialNumber,
              } : null,
              daysRemaining,
              isExpired,
              isSelfSigned,
              subjectAltNames,
              commonName,
              pinnedIp: pinned.pinnedIp,
            });
          } catch (innerErr) {
            cleanup();
            reject(innerErr);
          }
        }
      );

      socket.on('error', (err) => {
        if (!resolved) {
          resolved = true;
          cleanup();
          reject(err);
        }
      });
    } catch (err) {
      if (!resolved) {
        resolved = true;
        cleanup();
        reject(err);
      }
    }
  });
}

export interface SafeTcpOptions {
  timeoutMs?: number;
}

export interface SafeTcpSession {
  pinnedIp?: string;
  socket?: net.Socket;
  write(data: string | Buffer): Promise<void>;
  read(timeoutMs?: number): Promise<Buffer>;
  readUntil(predicate: (accumulated: Buffer) => boolean, timeoutMs?: number): Promise<Buffer>;
  close(): void;
}

/**
 * Connects securely to a remote TCP target over raw socket after validating and pinning the IP.
 * Enforces the exact same resolveAndPinTarget SSRF invariants as safeFetch and safeTlsHandshake.
 */
export async function safeTcpConnect(
  hostname: string,
  port: number,
  options: SafeTcpOptions = {}
): Promise<SafeTcpSession> {
  const { timeoutMs = 5000 } = options;

  // 1. Enforce strict SSRF defense: validates IP and asserts against RFC1918 / loopback / cloud metadata
  const pinned = await resolveAndPinTarget(hostname);

  return new Promise((resolve, reject) => {
    const socket = new net.Socket();
    let isConnected = false;
    let timer: NodeJS.Timeout | null = null;
    let accumulatedBuffer = Buffer.alloc(0);
    const dataListeners: Array<(chunk: Buffer) => void> = [];

    const cleanup = () => {
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
      if (!socket.destroyed) {
        socket.destroy();
      }
    };

    timer = setTimeout(() => {
      if (!isConnected) {
        cleanup();
        reject(new Error(`TCP connection timeout after ${timeoutMs}ms for ${hostname}:${port}`));
      }
    }, timeoutMs);

    socket.on('data', (chunk: Buffer) => {
      accumulatedBuffer = Buffer.concat([accumulatedBuffer, chunk]);
      for (const listener of dataListeners) {
        listener(chunk);
      }
    });

    socket.on('error', (err) => {
      if (!isConnected) {
        cleanup();
        reject(err);
      }
    });

    socket.connect(
      {
        host: pinned.pinnedIp,
        port,
      },
      () => {
        isConnected = true;
        if (timer) {
          clearTimeout(timer);
          timer = null;
        }

        const session: SafeTcpSession = {
          pinnedIp: pinned.pinnedIp,
          socket,
          async write(data: string | Buffer): Promise<void> {
            return new Promise((res, rej) => {
              if (socket.destroyed) {
                return rej(new Error('Cannot write to destroyed socket'));
              }
              socket.write(data, (err) => {
                if (err) rej(err);
                else res();
              });
            });
          },
          async read(readTimeoutMs: number = 3000): Promise<Buffer> {
            if (accumulatedBuffer.length > 0) {
              const buf = accumulatedBuffer;
              accumulatedBuffer = Buffer.alloc(0);
              return buf;
            }
            return new Promise((res) => {
              const timeout = setTimeout(() => {
                cleanupListener();
                res(Buffer.alloc(0));
              }, readTimeoutMs);

              const onData = (chunk: Buffer) => {
                clearTimeout(timeout);
                cleanupListener();
                accumulatedBuffer = Buffer.alloc(0);
                res(chunk);
              };

              const cleanupListener = () => {
                const idx = dataListeners.indexOf(onData);
                if (idx !== -1) dataListeners.splice(idx, 1);
              };

              dataListeners.push(onData);
            });
          },
          async readUntil(
            predicate: (accumulated: Buffer) => boolean,
            readTimeoutMs: number = 3000
          ): Promise<Buffer> {
            if (predicate(accumulatedBuffer)) {
              return accumulatedBuffer;
            }
            return new Promise((res) => {
              const timeout = setTimeout(() => {
                cleanupListener();
                res(accumulatedBuffer);
              }, readTimeoutMs);

              const onData = () => {
                if (predicate(accumulatedBuffer)) {
                  clearTimeout(timeout);
                  cleanupListener();
                  res(accumulatedBuffer);
                }
              };

              const cleanupListener = () => {
                const idx = dataListeners.indexOf(onData);
                if (idx !== -1) dataListeners.splice(idx, 1);
              };

              dataListeners.push(onData);
            });
          },
          close() {
            cleanup();
          },
        };

        resolve(session);
      }
    );
  });
}




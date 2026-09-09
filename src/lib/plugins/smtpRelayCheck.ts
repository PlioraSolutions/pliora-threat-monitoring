/**
 * PLIŌRA Threat Monitor — Open Mail Relay & SMTP Service Analyzer
 * 
 * =========================================================================================
 * ARCHITECTURAL & POLICY DECISION NOTICE (Wave 3 Spec §2):
 * 
 * Option 2A (Heuristic-Only, Aborted Dialogue) is exclusively implemented here.
 * Under no circumstances does this plugin ever send an actual email or relay a message
 * through customer or third-party infrastructure. 
 * 
 * Safety Posture:
 * 1. Probes the SMTP dialogue only up to "RCPT TO:<external-address>".
 * 2. If the server responds with 250 OK (indicating willingness to accept external relaying),
 *    the dialogue is DELIBERATELY AND IMMEDIATELY ABORTED by issuing "QUIT\r\n" and closing
 *    the TCP connection before "DATA" or any message payload is ever transmitted.
 * 3. Confidence Ceiling: Strictly capped at "MEDIUM" confidence. Because the relay is aborted
 *    before send commitment, this check represents a strong behavioral signal rather than
 *    conclusive end-to-end receipt confirmation.
 * 
 * Option 2B (Full Send Confirmation) is explicitly forbidden without a formal legal/product review.
 * =========================================================================================
 */

import { CheckPlugin, PluginContext, PluginResult, FindingSpec, PluginEvidenceSpec } from './types';
import { safeTcpConnect as defaultSafeTcpConnect } from '@/lib/security';

export const smtpRelayCheckPlugin: CheckPlugin = {
  id: 'smtp-relay-check',
  name: 'Open Mail Relay & SMTP Service Analyzer',
  category: 'EMAIL_SECURITY',
  defaultConfidence: 'MEDIUM', // Strict ceiling: Option 2A heuristic-only

  appliesTo(asset: { fqdn: string; type: string }) {
    return Boolean(asset.fqdn && asset.fqdn.includes('.'));
  },

  async run(asset, ctx: PluginContext): Promise<PluginResult> {
    const startTime = Date.now();
    const findings: FindingSpec[] = [];
    const evidence: PluginEvidenceSpec[] = [];
    const host = asset.fqdn.toLowerCase().trim();
    const tcpConnect = ctx.safeTcpConnect || defaultSafeTcpConnect;

    const portsToProbe = [25, 587];
    let suspectedOpenRelay = false;
    let relayPort = 0;
    let initialBanner = '';
    let rcptResponse = '';

    for (const port of portsToProbe) {
      try {
        const session = await tcpConnect(host, port, { timeoutMs: 2500 });

        try {
          // 1. Read initial 220 greeting banner
          const bannerBuf = await session.read(2000);
          initialBanner = bannerBuf.toString('utf-8').trim();

          if (!initialBanner.startsWith('220')) {
            // Not a standard SMTP banner
            continue;
          }

          // 2. Send EHLO
          await session.write('EHLO scanner.pliora.io\r\n');
          const ehloBuf = await session.read(2000);
          const ehloResp = ehloBuf.toString('utf-8');

          // If EHLO fails or rejected, fallback to HELO
          if (!ehloResp.startsWith('250')) {
            await session.write('HELO scanner.pliora.io\r\n');
            await session.read(2000);
          }

          // 3. Send MAIL FROM
          await session.write('MAIL FROM:<probe@pliora.io>\r\n');
          const mailFromBuf = await session.read(2000);
          const mailFromResp = mailFromBuf.toString('utf-8');

          if (!mailFromResp.startsWith('250')) {
            // Server requires auth or rejects sender
            continue;
          }

          // 4. Send RCPT TO for an external, non-local domain
          await session.write('RCPT TO:<relay-test@external-unrelated-domain.com>\r\n');
          const rcptBuf = await session.read(2000);
          rcptResponse = rcptBuf.toString('utf-8').trim();

          // =========================================================================
          // 5. CRITICAL SAFETY ABORT (Option 2A):
          // Immediately terminate session before DATA. No email is EVER sent.
          // =========================================================================
          try {
            await session.write('QUIT\r\n');
          } catch {}

          if (rcptResponse.startsWith('250')) {
            suspectedOpenRelay = true;
            relayPort = port;
            break; // Finding confirmed on this port
          }
        } finally {
          session.close();
        }
      } catch {
        // Port closed, filtered, or timeout
      }
    }

    if (suspectedOpenRelay) {
      findings.push({
        category: 'EMAIL_SECURITY',
        findingCode: 'SMTP-OPEN-RELAY-SUSPECTED',
        title: `Suspected Open Mail Relay on Port ${relayPort}`,
        description: `The mail server on ${host}:${relayPort} responded with "250 OK" when prompted to relay to an external destination (<relay-test@external-unrelated-domain.com>) without requiring authentication. Open mail relays are actively harvested by botnets to distribute spam, phishing, and ransomware while damaging your IP reputation. (Dialogue safely aborted before message transmission).`,
        severity: 'HIGH',
        confidence: 'MEDIUM', // STRICT DISCIPLINE: Option 2A heuristic signal capped at MEDIUM
        remediationGuidance: 'Configure your Mail Transfer Agent (Postfix, Sendmail, Exim, Exchange) to disallow unauthenticated relaying. Enforce "reject_unauth_destination" and require SMTP authentication (SASL/TLS) for external recipients.',
      });
    }

    evidence.push({
      checkType: 'SERVICE_BANNER',
      rawObservation: {
        host,
        portsChecked: portsToProbe,
        suspectedOpenRelay,
        relayPort: suspectedOpenRelay ? relayPort : null,
        initialBanner: initialBanner || null,
        rcptResponse: rcptResponse || null,
        optionPolicy: 'Option 2A (Heuristic-Only, Aborted Dialogue)',
        scannedAt: new Date().toISOString(),
      },
    });

    return {
      status: 'COMPLETED',
      evidence,
      findings,
      durationMs: Date.now() - startTime,
    };
  },
};

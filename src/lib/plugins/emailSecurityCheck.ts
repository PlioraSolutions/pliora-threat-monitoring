import { CheckPlugin, PluginContext, PluginResult, FindingSpec, PluginEvidenceSpec } from './types';
import { resilientResolveTxt } from '@/lib/dnsClient';

export const emailSecurityCheckPlugin: CheckPlugin = {
  id: 'email-security-check',
  name: 'Email Security & Anti-Spoofing Suite (SPF/DKIM/DMARC/MTA-STS)',
  category: 'EMAIL_SECURITY',
  defaultConfidence: 'CONFIRMED',

  appliesTo(asset: { fqdn: string; type: string }) {
    return Boolean(asset.fqdn && asset.fqdn.includes('.'));
  },

  async run(asset, ctx: PluginContext): Promise<PluginResult> {
    const startTime = Date.now();
    const findings: FindingSpec[] = [];
    const evidence: PluginEvidenceSpec[] = [];
    const host = asset.fqdn.toLowerCase().trim();

    let txtRecords: string[][] = [];
    try {
      txtRecords = await resilientResolveTxt(host);
    } catch {
      // Host may not have direct TXT records
    }

    const flatTxt = txtRecords.map((chunks) => chunks.join(''));

    // 1. SPF Inspection
    const spfRecords = flatTxt.filter((r) => r.toLowerCase().startsWith('v=spf1'));
    let spfRecord: string | null = null;

    if (spfRecords.length === 0) {
      findings.push({
        category: 'EMAIL_SECURITY',
        findingCode: 'EMAIL-SPF-MISSING',
        title: 'Missing SPF Record (Direct Domain Spoofing Risk)',
        description: `No Sender Policy Framework (SPF) record found on ${host}. Threat actors can forge email headers claiming to originate from @${host} without rejection by recipient mail servers.`,
        severity: 'HIGH',
        confidence: 'CONFIRMED',
        remediationGuidance: 'Publish a TXT record for your domain defining authorized sending servers (e.g., "v=spf1 include:_spf.google.com ~all").',
      });
    } else if (spfRecords.length > 1) {
      findings.push({
        category: 'EMAIL_SECURITY',
        findingCode: 'EMAIL-SPF-MULTIPLE',
        title: 'Multiple SPF Records Published (RFC 7208 PermError)',
        description: `Found ${spfRecords.length} conflicting SPF records on ${host}. RFC 7208 §3.2 specifies that publishing multiple SPF records causes recipient servers to return a PermError, disabling SPF protection.`,
        severity: 'HIGH',
        confidence: 'CONFIRMED',
        remediationGuidance: 'Merge all authorized mail mechanisms into a single v=spf1 TXT record.',
      });
      spfRecord = spfRecords[0];
    } else {
      spfRecord = spfRecords[0];
      const lowerSpf = spfRecord.toLowerCase();

      if (lowerSpf.includes('+all')) {
        findings.push({
          category: 'EMAIL_SECURITY',
          findingCode: 'EMAIL-SPF-PERMISSIVE-PLUS-ALL',
          title: 'Critical SPF Misconfiguration: +all Directive Allowed',
          description: `The SPF record for ${host} contains "+all", explicitly authorizing every IP address on the internet to send authenticated email as @${host}.`,
          severity: 'CRITICAL',
          confidence: 'CONFIRMED',
          remediationGuidance: 'Replace "+all" with "~all" (SoftFail) or "-all" (HardFail) immediately.',
        });
      } else if (lowerSpf.includes('?all')) {
        findings.push({
          category: 'EMAIL_SECURITY',
          findingCode: 'EMAIL-SPF-NEUTRAL-ALL',
          title: 'Weak SPF Enforcement: ?all (Neutral) Configured',
          description: `The SPF record for ${host} specifies "?all" (Neutral), providing no sender enforcement policy to receiving mail servers.`,
          severity: 'LOW',
          confidence: 'CONFIRMED',
          remediationGuidance: 'Update SPF record mechanism from ?all to ~all or -all for strict enforcement.',
        });
      }
    }

    // 2. DMARC Inspection
    let dmarcRecords: string[][] = [];
    const dmarcHost = `_dmarc.${host}`;
    try {
      dmarcRecords = await resilientResolveTxt(dmarcHost);
    } catch {}

    const flatDmarc = dmarcRecords.map((chunks) => chunks.join(''));
    const dmarcPolicy = flatDmarc.find((r) => r.toLowerCase().startsWith('v=dmarc1'));

    if (!dmarcPolicy) {
      findings.push({
        category: 'EMAIL_SECURITY',
        findingCode: 'EMAIL-DMARC-MISSING',
        title: 'Missing DMARC Policy (Domain Impersonation Vulnerability)',
        description: `No DMARC policy published at ${dmarcHost}. Without DMARC, receiving email servers cannot verify sender legitimacy or reject fraudulent spoofed mail.`,
        severity: 'HIGH',
        confidence: 'CONFIRMED',
        remediationGuidance: `Create a TXT record at _dmarc.${host} with at least "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@${host}".`,
      });
    } else {
      const lowerDmarc = dmarcPolicy.toLowerCase();
      const pMatch = lowerDmarc.match(/\bp=([a-z]+)\b/);
      const spMatch = lowerDmarc.match(/\bsp=([a-z]+)\b/);
      const ruaMatch = lowerDmarc.match(/\brua=([^;]+)\b/);

      const policy = pMatch ? pMatch[1] : '';
      const subdomainPolicy = spMatch ? spMatch[1] : '';

      if (policy === 'none') {
        findings.push({
          category: 'EMAIL_SECURITY',
          findingCode: 'EMAIL-DMARC-POLICY-NONE',
          title: 'DMARC Policy Set to Inactive Monitoring Mode (p=none)',
          description: `The DMARC policy for ${host} is set to "p=none". Unauthenticated spoofed emails are delivered to user inboxes without quarantine or rejection.`,
          severity: 'MEDIUM',
          confidence: 'CONFIRMED',
          remediationGuidance: 'Gradually transition DMARC policy from p=none to p=quarantine, and ultimately p=reject.',
        });
      }

      if (subdomainPolicy === 'none' && policy !== 'none') {
        findings.push({
          category: 'EMAIL_SECURITY',
          findingCode: 'EMAIL-DMARC-SUBDOMAIN-GAP',
          title: 'DMARC Subdomain Policy Exemption (sp=none)',
          description: `While apex domain enforcement is active (p=${policy}), subdomains are explicitly exempted with "sp=none". Attackers can spoof subdomains (e.g., billing.${host}) undetected.`,
          severity: 'MEDIUM',
          confidence: 'CONFIRMED',
          remediationGuidance: 'Remove "sp=none" or update it to match apex policy (sp=quarantine or sp=reject).',
        });
      }

      if (!ruaMatch || !ruaMatch[1].trim()) {
        findings.push({
          category: 'EMAIL_SECURITY',
          findingCode: 'EMAIL-DMARC-NO-REPORTING',
          title: 'DMARC Aggregate Telemetry Reporting Missing (rua=)',
          description: `DMARC record at ${dmarcHost} lacks an aggregate reporting mailbox ("rua="). You will receive no feedback on active spoofing or deliverability issues.`,
          severity: 'LOW',
          confidence: 'CONFIRMED',
          remediationGuidance: `Add a valid reporting recipient to your DMARC record (e.g. rua=mailto:dmarc@${host}).`,
        });
      }
    }

    // 3. DKIM Common Selector Presence Probes
    const commonDkimSelectors = ['google', 'default', 'k1', 's1', 'mail', 'selector1', 'dkim'];
    const discoveredSelectors: string[] = [];

    await Promise.all(
      commonDkimSelectors.map(async (sel) => {
        const dkimFqdn = `${sel}._domainkey.${host}`;
        try {
          const res = await resilientResolveTxt(dkimFqdn);
          if (res && res.length > 0) {
            discoveredSelectors.push(sel);
          }
        } catch {}
      })
    );

    // 4. BIMI Presence
    let bimiFound = false;
    try {
      const bimiRecords = await resilientResolveTxt(`default._bimi.${host}`);
      bimiFound = bimiRecords.some((chunks) => chunks.join('').toLowerCase().startsWith('v=bimi1'));
    } catch {}

    // 5. MTA-STS Policy Presence
    let mtaStsDns = false;
    let mtaStsPolicyActive = false;
    try {
      const mtaRecords = await resilientResolveTxt(`_mta-sts.${host}`);
      mtaStsDns = mtaRecords.some((chunks) => chunks.join('').toLowerCase().startsWith('v=stsv1'));
      if (mtaStsDns) {
        const policyRes = await ctx.safeFetch(`https://mta-sts.${host}/.well-known/mta-sts.txt`, {
          timeoutMs: 3000,
        });
        if (policyRes.ok) {
          const text = await policyRes.text();
          if (text.includes('version: STSv1')) {
            mtaStsPolicyActive = true;
          }
        }
      }
    } catch {}

    evidence.push({
      checkType: 'EMAIL_SECURITY',
      rawObservation: {
        host,
        spf: {
          present: Boolean(spfRecord),
          record: spfRecord,
          multipleRecords: spfRecords.length > 1,
        },
        dmarc: {
          present: Boolean(dmarcPolicy),
          record: dmarcPolicy || null,
        },
        dkim: {
          probedSelectors: commonDkimSelectors,
          discoveredSelectors,
        },
        bimi: { present: bimiFound },
        mtaSts: {
          dnsPublished: mtaStsDns,
          policyActive: mtaStsPolicyActive,
        },
        checkedAt: new Date().toISOString(),
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

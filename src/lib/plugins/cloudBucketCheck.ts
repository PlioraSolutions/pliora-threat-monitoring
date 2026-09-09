import { CheckPlugin, PluginContext, PluginResult, FindingSpec, PluginEvidenceSpec } from './types';
import { generateBucketCandidates } from './cloudBuckets/candidates';

interface BucketProbeResult {
  candidate: string;
  provider: 'AWS_S3' | 'GOOGLE_CLOUD_STORAGE' | 'AZURE_BLOB';
  url: string;
  status: number;
  isPublicListable: boolean;
  isPrivateExists: boolean;
  sampleKeys?: string[];
}

export const cloudBucketCheckPlugin: CheckPlugin = {
  id: 'cloud-bucket-check',
  name: 'Cloud Storage Bucket Exposure Analyzer',
  category: 'CLOUD_STORAGE',
  defaultConfidence: 'CONFIRMED',

  appliesTo(asset: { fqdn: string; type: string }) {
    return Boolean(asset.fqdn && asset.fqdn.includes('.'));
  },

  async run(asset, ctx: PluginContext): Promise<PluginResult> {
    const startTime = Date.now();
    const findings: FindingSpec[] = [];
    const evidence: PluginEvidenceSpec[] = [];
    const host = asset.fqdn.toLowerCase().trim();

    // Generate permutation candidate names bounded to standard convention
    const candidates = generateBucketCandidates(host);
    // Prioritize top candidates for scan cycle
    const scanCandidates = candidates.slice(0, 8);

    const probedBuckets: BucketProbeResult[] = [];

    // Probe helper
    async function probeEndpoint(
      candidate: string,
      provider: 'AWS_S3' | 'GOOGLE_CLOUD_STORAGE' | 'AZURE_BLOB',
      url: string
    ) {
      try {
        const res = await ctx.safeFetch(url, {
          method: 'GET',
          timeoutMs: Math.min(ctx.timeoutMs || 2500, 2000),
          headers: {
            Accept: 'application/xml,text/xml,*/*',
            'User-Agent': 'Mozilla/5.0 (compatible; PlioraThreatMonitor/1.0; +https://pliora.io)',
          },
        });

        const body = await res.text();

        // Anti-False-Positive Filter: Ensure response is genuine XML, not an SPA HTML 200
        const isHtml = body.toLowerCase().includes('<!doctype html') || body.toLowerCase().includes('<html');
        if (isHtml) {
          return;
        }

        // 1. Check for authentic public listing
        const isS3OrGcsListing =
          res.status === 200 &&
          (body.includes('<ListBucketResult') || body.includes('<ListAllMyBucketsResult')) &&
          body.includes('<Contents>');

        const isAzureListing =
          res.status === 200 &&
          (body.includes('<EnumerationResults') || body.includes('<Blobs>')) &&
          body.includes('<Blob>');

        if (isS3OrGcsListing || isAzureListing) {
          // Extract sample keys if available
          const keys: string[] = [];
          const keyMatches = body.match(/<Key>([^<]+)<\/Key>/g);
          if (keyMatches) {
            for (const km of keyMatches.slice(0, 5)) {
              const cleaned = km.replace(/<\/?Key>/g, '');
              keys.push(cleaned);
            }
          }

          probedBuckets.push({
            candidate,
            provider,
            url,
            status: res.status,
            isPublicListable: true,
            isPrivateExists: false,
            sampleKeys: keys,
          });
          return;
        }

        // 2. Check for private existing bucket (AccessDenied)
        const isAccessDenied =
          (res.status === 403 || res.status === 401) &&
          (body.includes('AccessDenied') ||
            body.includes('AuthenticationFailed') ||
            body.includes('AuthorizationFailure') ||
            body.includes('InvalidAccessKeyId'));

        if (isAccessDenied) {
          probedBuckets.push({
            candidate,
            provider,
            url,
            status: res.status,
            isPublicListable: false,
            isPrivateExists: true,
          });
        }
      } catch {
        // DNS ENOTFOUND or network error indicates bucket host does not exist
      }
    }

    // Run probes across AWS, GCS, Azure concurrently
    await Promise.all(
      scanCandidates.map(async (candidate) => {
        await Promise.all([
          probeEndpoint(candidate, 'AWS_S3', `https://${candidate}.s3.amazonaws.com`),
          probeEndpoint(candidate, 'GOOGLE_CLOUD_STORAGE', `https://storage.googleapis.com/${candidate}`),
          probeEndpoint(
            candidate,
            'AZURE_BLOB',
            `https://${candidate}.blob.core.windows.net?comp=list&restype=container`
          ),
        ]);
      })
    );

    // Transform probe results into findings
    for (const bucket of probedBuckets) {
      if (bucket.isPublicListable) {
        const findingCode =
          bucket.provider === 'AWS_S3'
            ? 'CLOUD-BUCKET-PUBLIC-LISTING-S3'
            : bucket.provider === 'GOOGLE_CLOUD_STORAGE'
            ? 'CLOUD-BUCKET-PUBLIC-LISTING-GCS'
            : 'CLOUD-BUCKET-PUBLIC-LISTING-AZURE';

        const providerName =
          bucket.provider === 'AWS_S3'
            ? 'Amazon Web Services (AWS S3)'
            : bucket.provider === 'GOOGLE_CLOUD_STORAGE'
            ? 'Google Cloud Storage (GCS)'
            : 'Microsoft Azure Blob Storage';

        findings.push({
          category: 'CLOUD_STORAGE',
          findingCode,
          title: `Publicly Listable ${providerName} Bucket: ${bucket.candidate}`,
          description: `Cloud storage bucket "${bucket.candidate}" on ${providerName} is configured with public-read permissions. An unauthenticated external party can enumerate, read, and download all stored files and assets. Sample objects: ${
            bucket.sampleKeys?.join(', ') || 'Available via anonymous XML listing'
          }.`,
          severity: 'HIGH',
          confidence: 'CONFIRMED',
          remediationGuidance: `Immediately block public access on bucket "${bucket.candidate}". Enable S3 Block Public Access / GCS uniform bucket-level access and remove anonymous read ACLs.`,
        });
      } else if (bucket.isPrivateExists) {
        findings.push({
          category: 'CLOUD_STORAGE',
          findingCode: 'CLOUD-BUCKET-EXISTS-PRIVATE',
          title: `Discovered Private Cloud Storage Bucket (${bucket.candidate})`,
          description: `Cloud storage bucket "${bucket.candidate}" (${bucket.provider}) exists and correctly returns Access Denied. No public data exposure was detected.`,
          severity: 'INFORMATIONAL',
          confidence: 'CONFIRMED',
          remediationGuidance: 'Maintain existing private access controls and monitor bucket access logs for unauthorized enumeration attempts.',
        });
      }
    }

    evidence.push({
      checkType: 'CLOUD_BUCKET_SCAN',
      rawObservation: {
        host,
        candidatesTested: scanCandidates.length,
        probedBuckets,
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

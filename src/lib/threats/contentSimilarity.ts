/**
 * ============================================================================
 * PLIŌRA STRUCTURAL CONTENT SIMILARITY DETECTOR (§B.2 / §3.1)
 * ============================================================================
 * 
 * Compares structural DOM similarity and static-asset references of a candidate
 * look-alike / typosquatted domain against a verified customer site.
 * 
 * Key capabilities:
 * 1. Tag Frequency Vector Cosine Similarity (DOM layout distribution)
 * 2. Phishing Login Form Fingerprinting (matching password & credential input names)
 * 3. Static Asset Path Overlap (shared images, brand icons, CSS filenames)
 * 
 * Lightweight, deterministic, and side-effect-free (no headless browser required).
 * ============================================================================
 */

export interface ContentSimilarityResult {
  similarityScore: number; // 0 to 100
  tagDistributionSimilarity: number; // 0.0 to 1.0
  hasMatchingLoginForm: boolean;
  hasSharedAssets: boolean;
  sharedAssetNames: string[];
  details: {
    legitimateTagCount: number;
    candidateTagCount: number;
    detectedForms: {
      legitimateHasLogin: boolean;
      candidateHasLogin: boolean;
    };
  };
}

/**
 * Extracts frequency vector of HTML tags from raw HTML string.
 */
function extractTagFrequency(html: string): Map<string, number> {
  const tagRegex = /<([a-zA-Z0-9]+)(\s|>|\/)/g;
  const frequencies = new Map<string, number>();
  let match: RegExpExecArray | null;

  while ((match = tagRegex.exec(html)) !== null) {
    const tagName = match[1].toLowerCase();
    // Exclude basic framing doctype/html/head/body to focus on page body structure
    if (['!doctype', 'html', 'head', 'meta', 'title'].includes(tagName)) {
      continue;
    }
    frequencies.set(tagName, (frequencies.get(tagName) || 0) + 1);
  }

  return frequencies;
}

/**
 * Calculates Cosine Similarity between two frequency vectors.
 */
function calculateCosineSimilarity(vecA: Map<string, number>, vecB: Map<string, number>): number {
  if (vecA.size === 0 || vecB.size === 0) return 0.0;

  let dotProduct = 0;
  let normA = 0;
  let normB = 0;

  for (const [key, valA] of Array.from(vecA.entries())) {
    normA += valA * valA;
    const valB = vecB.get(key) || 0;
    dotProduct += valA * valB;
  }

  for (const valB of Array.from(vecB.values())) {
    normB += valB * valB;
  }

  if (normA === 0 || normB === 0) return 0.0;

  return dotProduct / (Math.sqrt(normA) * Math.sqrt(normB));
}

/**
 * Detects whether an HTML string contains a login/credential entry form.
 */
function detectLoginForm(html: string): { hasLoginForm: boolean; inputNames: string[] } {
  const lowerHtml = html.toLowerCase();
  const hasPasswordInput = /<input[^>]+type=["']password["']/i.test(lowerHtml);
  const inputNames: string[] = [];

  const inputNameRegex = /<input[^>]+name=["']([^"']+)["']/gi;
  let match: RegExpExecArray | null;
  while ((match = inputNameRegex.exec(html)) !== null) {
    inputNames.push(match[1].toLowerCase());
  }

  const hasCredentialName = inputNames.some((name) =>
    ['user', 'username', 'email', 'login', 'account', 'auth', 'pass', 'password'].includes(name)
  );

  return {
    hasLoginForm: hasPasswordInput || hasCredentialName,
    inputNames,
  };
}

/**
 * Extracts asset basenames from src/href attributes (e.g. logo.png, main.css).
 */
function extractAssetBasenames(html: string): Set<string> {
  const assetRegex = /(?:src|href)=["']([^"']+\.(?:png|jpg|jpeg|svg|gif|ico|webp|css|js))(?:\?[^"']*)?["']/gi;
  const assets = new Set<string>();
  let match: RegExpExecArray | null;

  while ((match = assetRegex.exec(html)) !== null) {
    const rawPath = match[1];
    const parts = rawPath.split('/');
    const filename = parts[parts.length - 1].toLowerCase();
    if (filename.length > 3) {
      assets.add(filename);
    }
  }

  return assets;
}

/**
 * Computes structural content similarity between legitimate website HTML and candidate look-alike HTML.
 */
export function computeContentSimilarity(
  legitimateHtml: string,
  candidateHtml: string
): ContentSimilarityResult {
  if (!legitimateHtml || !candidateHtml) {
    return {
      similarityScore: 0,
      tagDistributionSimilarity: 0,
      hasMatchingLoginForm: false,
      hasSharedAssets: false,
      sharedAssetNames: [],
      details: {
        legitimateTagCount: 0,
        candidateTagCount: 0,
        detectedForms: { legitimateHasLogin: false, candidateHasLogin: false },
      },
    };
  }

  // 1. Tag frequency vector similarity
  const tagsLegit = extractTagFrequency(legitimateHtml);
  const tagsCand = extractTagFrequency(candidateHtml);
  const tagSimilarity = calculateCosineSimilarity(tagsLegit, tagsCand);

  // 2. Form & Credential field matching
  const formLegit = detectLoginForm(legitimateHtml);
  const formCand = detectLoginForm(candidateHtml);

  // Candidate is dangerous if it serves a login form matching legitimate auth inputs or has a password field
  const hasMatchingLoginForm =
    formCand.hasLoginForm &&
    (formLegit.hasLoginForm || /<input[^>]+type=["']password["']/i.test(candidateHtml));

  // 3. Static asset matching
  const assetsLegit = extractAssetBasenames(legitimateHtml);
  const assetsCand = extractAssetBasenames(candidateHtml);

  const sharedAssetNames: string[] = [];
  for (const asset of Array.from(assetsCand)) {
    if (assetsLegit.has(asset)) {
      sharedAssetNames.push(asset);
    }
  }
  const hasSharedAssets = sharedAssetNames.length > 0;

  // 4. Overall Weighted Score (0 to 100)
  // - Tag Distribution: up to 50 pts
  // - Login Form Match: up to 35 pts (heavy indicator for phishing)
  // - Shared Brand Assets: up to 15 pts
  let rawScore = Math.round(tagSimilarity * 50);
  if (hasMatchingLoginForm) rawScore += 35;
  if (hasSharedAssets) {
    rawScore += Math.min(15, sharedAssetNames.length * 5);
  }

  const similarityScore = Math.min(100, Math.max(0, rawScore));

  return {
    similarityScore,
    tagDistributionSimilarity: Number(tagSimilarity.toFixed(4)),
    hasMatchingLoginForm,
    hasSharedAssets,
    sharedAssetNames,
    details: {
      legitimateTagCount: Array.from(tagsLegit.values()).reduce((a, b) => a + b, 0),
      candidateTagCount: Array.from(tagsCand.values()).reduce((a, b) => a + b, 0),
      detectedForms: {
        legitimateHasLogin: formLegit.hasLoginForm,
        candidateHasLogin: formCand.hasLoginForm,
      },
    },
  };
}

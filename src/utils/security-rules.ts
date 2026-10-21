/**
 * PhishShield AI - Core Security Rules & Deterministic Heuristics
 * Decoupled, pure-logic cybersecurity validation & passive dissection engine.
 */

export interface UrlInspectionResult {
  url: string;
  isValid: boolean;
  protocol: string;
  hostname: string;
  pathname: string;
  isHttps: boolean;
  isIpAddress: boolean;
  isShortener: boolean;
  isSuspiciousTld: boolean;
  hasBrandSpoofing: boolean;
  spoofedBrand?: string;
  entropy: number;
  subdomainDepth: number;
  riskScore: number;
  riskTier: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'SAFE';
  reasons: string[];
  recommendations: string[];
}

export interface HeuristicTrigger {
  ruleId: string;
  category: 'URGENCY' | 'CREDENTIAL_HARVEST' | 'IMPERSONATION' | 'SUSPICIOUS_LINK' | 'FINANCIAL_EXTORTION';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  points: number;
  description: string;
  evidence: string;
}

export interface MessageAnalysisResult {
  riskScore: number; // 0 to 100 strictly clamped
  riskTier: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'SAFE';
  confidence: number;
  triggers: HeuristicTrigger[];
  extractedUrls: UrlInspectionResult[];
  scrubbedPayload: string;
  scrubbedCount: number;
  redactedTypes: string[];
  summary: string;
  recommendations: string[];
  isLegitimateHint: boolean;
}

// Common Brand Lexicon for Typosquatting / Impersonation Detection
export const KNOWN_BRANDS = [
  { brand: 'paypal', legitimateDomains: ['paypal.com', 'paypal.me'] },
  { brand: 'chase', legitimateDomains: ['chase.com', 'jpmorganchase.com'] },
  { brand: 'wells fargo', legitimateDomains: ['wellsfargo.com'] },
  { brand: 'bank of america', legitimateDomains: ['bankofamerica.com', 'bofa.com'] },
  { brand: 'apple', legitimateDomains: ['apple.com', 'icloud.com'] },
  { brand: 'google', legitimateDomains: ['google.com', 'accounts.google.com', 'gmail.com'] },
  { brand: 'microsoft', legitimateDomains: ['microsoft.com', 'live.com', 'office.com', 'outlook.com'] },
  { brand: 'amazon', legitimateDomains: ['amazon.com', 'amazon.co.uk'] },
  { brand: 'netflix', legitimateDomains: ['netflix.com'] },
  { brand: 'usps', legitimateDomains: ['usps.com'] },
  { brand: 'dhl', legitimateDomains: ['dhl.com'] },
  { brand: 'fedex', legitimateDomains: ['fedex.com'] }
];

// Suspicious High-Risk TLDs frequently abused in rapid-disposal phishing
export const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'buzz', 'icu', 'cam', 'rest', 'live', 'ru', 'cn', 'work', 'gq', 'cf', 'tk', 'ml', 'ga', 'club'
]);

// URL Shorteners
export const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly', 'ow.ly', 'cutt.ly', 'rb.gy'
]);

/**
 * Scrubs passwords, OTPs, PINs, SSNs, credit cards, and private tokens prior to LLM or storage.
 */
export function scrubSecrets(input: string): { sanitized: string; scrubbedCount: number; redactedTypes: string[] } {
  if (!input) return { sanitized: '', scrubbedCount: 0, redactedTypes: [] };

  let count = 0;
  const types = new Set<string>();
  let text = input;

  // Redact OTPs (4-8 digits near verification keywords)
  const otpRegex = /\b(?:otp(?:\s+code)?|one-time passcode|verification code|security code|passcode|token)[\s:=#\-]+(\d{4,8})\b/gi;
  text = text.replace(otpRegex, (_match, code) => {
    count++;
    types.add('OTP / Verification Code');
    return `[SECRET SCRUBBED: OTP ${code.length}-digit]`;
  });

  // Redact Passwords / PINs in explicit format
  const passRegex = /\b(?:password|passwd|pwd|card pin|atm pin|pin code)[\s:=#\-]+([^\s,;]+)/gi;
  text = text.replace(passRegex, () => {
    count++;
    types.add('Password / PIN Credential');
    return '[SECRET SCRUBBED: Password/PIN]';
  });

  // Redact Credit Card Numbers (13-19 digits, Luhn pattern)
  const ccRegex = /\b(?:\d{4}[ -]?){3}\d{4}\b/g;
  text = text.replace(ccRegex, (cc) => {
    count++;
    types.add('Credit Card Number');
    return `[SECRET SCRUBBED: Card ending in ${cc.slice(-4)}]`;
  });

  // Redact SSN pattern (3-2-4)
  const ssnRegex = /\b\d{3}-\d{2}-\d{4}\b/g;
  text = text.replace(ssnRegex, () => {
    count++;
    types.add('Social Security Number (SSN)');
    return '[SECRET SCRUBBED: SSN]';
  });

  return {
    sanitized: text,
    scrubbedCount: count,
    redactedTypes: Array.from(types)
  };
}

/**
 * Extracts all URLs from raw text
 */
export function extractUrls(text: string): string[] {
  if (!text) return [];
  const urlRegex = /(?:https?:\/\/|www\.)[^\s<>"'{}|\\^`]+[^\s<>"'{}|\\^`.,;:?!]/gi;
  const matches = text.match(urlRegex) || [];
  
  // Normalize matches (add https:// if missing)
  const uniqueUrls = Array.from(new Set(matches.map(u => u.startsWith('http') ? u : `https://${u}`)));
  return uniqueUrls;
}

/**
 * Calculates Shannon entropy of a string (higher = randomized or machine-generated)
 */
export function calculateShannonEntropy(str: string): number {
  if (!str) return 0;
  const freq: { [key: string]: number } = {};
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    freq[char] = (freq[char] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const char in freq) {
    const p = freq[char] / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(2));
}

/**
 * Passive RFC 3986 URL Dissection - Pure Lexical & Structural Analysis (No outbound socket requests)
 */
export function inspectUrl(urlString: string): UrlInspectionResult {
  const reasons: string[] = [];
  const recommendations: string[] = [];

  if (!urlString || typeof urlString !== 'string') {
    return {
      url: urlString || '',
      isValid: false,
      protocol: '',
      hostname: '',
      pathname: '',
      isHttps: false,
      isIpAddress: false,
      isShortener: false,
      isSuspiciousTld: false,
      hasBrandSpoofing: false,
      entropy: 0,
      subdomainDepth: 0,
      riskScore: 90,
      riskTier: 'HIGH',
      reasons: ['Malformed or empty URL input.'],
      recommendations: ['Provide a syntactically valid URL string (RFC 3986).']
    };
  }

  let parsed: URL;
  try {
    parsed = new URL(urlString.startsWith('http') ? urlString : `https://${urlString}`);
  } catch (_e) {
    return {
      url: urlString,
      isValid: false,
      protocol: '',
      hostname: '',
      pathname: '',
      isHttps: false,
      isIpAddress: false,
      isShortener: false,
      isSuspiciousTld: false,
      hasBrandSpoofing: false,
      entropy: 0,
      subdomainDepth: 0,
      riskScore: 85,
      riskTier: 'HIGH',
      reasons: ['RFC 3986 parsing failure: Invalid URI syntax.'],
      recommendations: ['Do not navigate to broken or obfuscated links.']
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  const protocol = parsed.protocol.toLowerCase();
  const pathname = parsed.pathname;
  const isHttps = protocol === 'https:';

  // IPv4 / IPv6 literal hostname detection (bypasses domain registration records)
  const isIpv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  const isIpv6 = hostname.startsWith('[') && hostname.endsWith(']');
  const isIpAddress = isIpv4 || isIpv6;

  // Domain segments
  const domainParts = hostname.split('.');
  const tld = domainParts.length > 1 ? domainParts[domainParts.length - 1] : '';
  const isSuspiciousTld = SUSPICIOUS_TLDS.has(tld);
  const isShortener = URL_SHORTENERS.has(hostname);
  const subdomainDepth = Math.max(0, domainParts.length - 2);
  const entropy = calculateShannonEntropy(hostname);

  let riskScore = 5;

  if (!isHttps) {
    riskScore += 25;
    reasons.push('Insecure cleartext HTTP scheme (traffic unencrypted).');
    recommendations.push('Legitimate authentication portals mandate TLS (HTTPS).');
  }

  if (isIpAddress) {
    riskScore += 50;
    reasons.push(`Direct IP hostname detected (${hostname}). Legitimate institutions never route consumers to raw IPs.`);
    recommendations.push('Immediate red flag: Block connection at border gateway.');
  }

  if (isSuspiciousTld) {
    riskScore += 30;
    reasons.push(`Uncommon or high-abuse TLD (.${tld}) frequently used in disposable phishing domains.`);
    recommendations.push('Verify legitimacy of the organization on official channels.');
  }

  if (isShortener) {
    riskScore += 35;
    reasons.push(`URL shortening service (${hostname}) conceals final target host.`);
    recommendations.push('Unfurl shortener using a dedicated security sandbox before clicking.');
  }

  if (subdomainDepth >= 3) {
    riskScore += 20;
    reasons.push(`Excessive subdomain nesting (${subdomainDepth} levels) indicative of DNS tunneling or evasion.`);
  }

  if (entropy > 4.2) {
    riskScore += 15;
    reasons.push(`Elevated hostname entropy (${entropy} bits/char) suggesting domain generation algorithm (DGA).`);
  }

  // Brand spoofing audit
  let hasBrandSpoofing = false;
  let spoofedBrandName: string | undefined;

  for (const b of KNOWN_BRANDS) {
    const brandName = b.brand.toLowerCase().replace(/\s+/g, '');
    const cleanHost = hostname.replace(/-/g, '');

    if (cleanHost.includes(brandName)) {
      const isLegit = b.legitimateDomains.some(ld => hostname === ld || hostname.endsWith(`.${ld}`));
      if (!isLegit) {
        hasBrandSpoofing = true;
        spoofedBrandName = b.brand;
        riskScore += 45;
        reasons.push(`Brand impersonation alert: Contains "${b.brand}" but does not belong to authorized domains (${b.legitimateDomains.join(', ')}).`);
        recommendations.push(`Typosquatting/homograph risk. Navigate directly to https://${b.legitimateDomains[0]} instead.`);
        break;
      }
    }
  }

  // Legitimate top domains false-positive dampener
  const isVerifiedLegit = KNOWN_BRANDS.some(b => b.legitimateDomains.some(ld => hostname === ld || hostname.endsWith(`.${ld}`)));
  if (isVerifiedLegit && !isIpAddress && !isShortener) {
    riskScore = Math.min(riskScore, 10);
    reasons.push('Hostname verified against recognized authentic enterprise infrastructure.');
  }

  // Score clamping between 0 and 100
  riskScore = Math.max(0, Math.min(100, riskScore));

  let riskTier: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'SAFE' = 'SAFE';
  if (riskScore >= 75) riskTier = 'CRITICAL';
  else if (riskScore >= 50) riskTier = 'HIGH';
  else if (riskScore >= 25) riskTier = 'MEDIUM';

  if (recommendations.length === 0) {
    recommendations.push('Standard browsing hygiene: Confirm address bar matches expected destination.');
  }

  return {
    url: urlString,
    isValid: true,
    protocol,
    hostname,
    pathname,
    isHttps,
    isIpAddress,
    isShortener,
    isSuspiciousTld,
    hasBrandSpoofing,
    spoofedBrand: spoofedBrandName,
    entropy,
    subdomainDepth,
    riskScore,
    riskTier,
    reasons,
    recommendations
  };
}

/**
 * Deterministic Heuristic Message Analyzer
 */
export function analyzeMessageHeuristics(params: {
  text: string;
  sender?: string;
  channel?: string;
}): MessageAnalysisResult {
  const rawText = params.text || '';
  const sender = (params.sender || '').trim();
  const triggers: HeuristicTrigger[] = [];

  // 1. Scrub secrets
  const scrubResult = scrubSecrets(rawText);
  const text = scrubResult.sanitized;

  // Edge Case: Empty input
  if (!text.trim()) {
    return {
      riskScore: 0,
      riskTier: 'SAFE',
      confidence: 100,
      triggers: [],
      extractedUrls: [],
      scrubbedPayload: '',
      scrubbedCount: 0,
      redactedTypes: [],
      summary: 'No message content provided for evaluation.',
      recommendations: ['Paste an email body, SMS text, or communication snippet to analyze.'],
      isLegitimateHint: false
    };
  }

  let totalScore = 0;

  // 2. Check Urgency / Coercion Tactics
  const urgencyWords = [
    'immediately', 'urgent', 'urgently', 'suspended', 'permanent termination',
    'within 24 hours', 'within 1 hour', 'account frozen', 'fund freeze',
    'action required', 'unauthorized access', 'unauthorized login', 'security breach',
    'final notice', 'legal action', 'arrest warrant'
  ];
  const matchedUrgency: string[] = [];
  for (const word of urgencyWords) {
    const reg = new RegExp(`\\b${word}\\b`, 'gi');
    if (reg.test(rawText)) {
      matchedUrgency.push(word);
    }
  }
  if (matchedUrgency.length > 0) {
    const pts = Math.min(35, matchedUrgency.length * 12);
    totalScore += pts;
    triggers.push({
      ruleId: 'RULE-URG-01',
      category: 'URGENCY',
      severity: matchedUrgency.length >= 2 ? 'CRITICAL' : 'HIGH',
      points: pts,
      description: 'Manufactured Urgency & Panic Induction',
      evidence: `Found ${matchedUrgency.length} coercive urgency terms: "${matchedUrgency.slice(0, 4).join('", "')}"`
    });
  }

  // 3. Credential & Financial Harvesting Tactics
  const harvestKeywords = [
    'password', 'passcode', 'otp', 'verification code', 'pin', 'cvv', 'card number',
    'social security', 'ssn', 'bank account', 'routing number', 'wire transfer',
    'bitcoin', 'crypto', 'gift card', 'confirm credentials', 're-authenticate',
    'unlock your account'
  ];
  const matchedHarvest: string[] = [];
  for (const kw of harvestKeywords) {
    const reg = new RegExp(`\\b${kw}\\b`, 'gi');
    if (reg.test(rawText)) {
      matchedHarvest.push(kw);
    }
  }
  if (matchedHarvest.length > 0) {
    const pts = Math.min(45, matchedHarvest.length * 15);
    totalScore += pts;
    triggers.push({
      ruleId: 'RULE-HARV-02',
      category: 'CREDENTIAL_HARVEST',
      severity: 'CRITICAL',
      points: pts,
      description: 'Credential Exfiltration Request',
      evidence: `Message requests sensitive credentials or financial actions: "${matchedHarvest.slice(0, 4).join('", "')}"`
    });
  }

  // 4. Sender Address Inspection
  if (sender) {
    const senderLower = sender.toLowerCase();
    for (const b of KNOWN_BRANDS) {
      const brandClean = b.brand.toLowerCase().replace(/\s+/g, '');
      if (senderLower.includes(brandClean)) {
        const isLegit = b.legitimateDomains.some(ld => senderLower.endsWith(`@${ld}`) || senderLower.includes(`@${ld}`));
        if (!isLegit) {
          totalScore += 30;
          triggers.push({
            ruleId: 'RULE-SND-03',
            category: 'IMPERSONATION',
            severity: 'CRITICAL',
            points: 30,
            description: 'Sender Domain Impersonation / Lookalike',
            evidence: `Sender "${sender}" evokes "${b.brand}" but does not originate from verified domains (${b.legitimateDomains.join(', ')}).`
          });
          break;
        }
      }
    }

    if (senderLower.includes('.xyz') || senderLower.includes('.top') || senderLower.includes('.ru') || senderLower.includes('resolution')) {
      totalScore += 20;
      triggers.push({
        ruleId: 'RULE-SND-04',
        category: 'IMPERSONATION',
        severity: 'HIGH',
        points: 20,
        description: 'Untrusted Sender Top-Level Domain',
        evidence: `Sender domain "${sender}" uses a suspicious or disposable namespace.`
      });
    }
  }

  // 5. URL Extraction & Inspection
  const extractedRawUrls = extractUrls(rawText);
  const extractedUrlResults = extractedRawUrls.map(u => inspectUrl(u));

  if (extractedUrlResults.length > 0) {
    const highRiskUrl = extractedUrlResults.find(u => u.riskTier === 'CRITICAL' || u.riskTier === 'HIGH');
    if (highRiskUrl) {
      const pts = 25;
      totalScore += pts;
      triggers.push({
        ruleId: 'RULE-URL-05',
        category: 'SUSPICIOUS_LINK',
        severity: 'CRITICAL',
        points: pts,
        description: 'Malicious / Impersonated Embedded Link',
        evidence: `Extracted link "${highRiskUrl.url}" exhibits risk markers: ${highRiskUrl.reasons.join('; ')}`
      });
    }
  }

  // 6. Legitimate Benign Indicators Dampener
  const benignIndicators = [
    'google meet', 'zoom.us', 'microsoft teams', 'calendar invite', 'sprint retrospective',
    'weekly sync', 'confluence', 'jira', 'github commit', 'internal planning'
  ];
  let benignCount = 0;
  for (const b of benignIndicators) {
    if (rawText.toLowerCase().includes(b)) {
      benignCount++;
    }
  }

  const isLegitimateHint = benignCount >= 2 && matchedHarvest.length === 0 && matchedUrgency.length === 0;
  if (isLegitimateHint) {
    totalScore = Math.max(0, totalScore - 50);
  }

  // Score clamping 0 to 100
  totalScore = Math.max(0, Math.min(100, totalScore));

  // Determine Tier
  let riskTier: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'SAFE' = 'SAFE';
  if (totalScore >= 75) riskTier = 'CRITICAL';
  else if (totalScore >= 50) riskTier = 'HIGH';
  else if (totalScore >= 25) riskTier = 'MEDIUM';

  // Recommendations
  const recommendations: string[] = [];
  if (riskTier === 'CRITICAL') {
    recommendations.push('Do NOT click any links, open attachments, or input passwords/OTPs.');
    recommendations.push('Flag and report the email/SMS to your organization\'s SecOps / Incident Response desk.');
    recommendations.push('If credentials were provided, invalidate active sessions and reset passwords immediately from a secure device.');
  } else if (riskTier === 'HIGH' || riskTier === 'MEDIUM') {
    recommendations.push('Verify the request out-of-band via an established direct contact channel (phone/in-person).');
    recommendations.push('Inspect hyperlink destinations carefully without navigating to them directly.');
  } else {
    recommendations.push('Standard defensive posture: Verify sender address matches expected internal address book.');
  }

  // Summary
  let summary = '';
  if (riskTier === 'CRITICAL') {
    summary = `High-confidence phishing indicators identified. The communication employs coercive urgency pressure, credential harvesting patterns, or unauthorized domain spoofing.`;
  } else if (riskTier === 'HIGH') {
    summary = `Elevated risk signals detected. The message contains suspicious characteristics that warrant analyst caution.`;
  } else if (riskTier === 'MEDIUM') {
    summary = `Moderate caution advised. Some non-standard language or link redirection patterns were flagged.`;
  } else {
    summary = `No significant phishing or deception indicators detected. Message aligns with standard benign correspondence.`;
  }

  return {
    riskScore: totalScore,
    riskTier,
    confidence: triggers.length > 0 ? 94 : 88,
    triggers,
    extractedUrls: extractedUrlResults,
    scrubbedPayload: text,
    scrubbedCount: scrubResult.scrubbedCount,
    redactedTypes: scrubResult.redactedTypes,
    summary,
    recommendations,
    isLegitimateHint
  };
}

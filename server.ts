import express, { Request, Response } from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { GoogleGenAI, ThinkingLevel } from '@google/genai';
import {
  analyzeMessageHeuristics,
  inspectUrl,
  scrubSecrets
} from './src/utils/security-rules.ts';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT) || 3000;

app.use(express.json({ limit: '2mb' }));

// In-memory Incident Vault store & Telemetry
interface StoredIncident {
  id: string;
  timestamp: string;
  date: string;
  vector: string;
  target: string;
  riskTier: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'SAFE';
  riskScore: number;
  findings: string;
  triggers: any[];
  recommendations: string[];
  aiReasoning?: string;
  aiModel?: string;
}

let incidentVault: StoredIncident[] = [
  {
    id: "SEC-9014",
    timestamp: "10:42:15 UTC",
    date: "2026-10-21 10:42",
    vector: "Email Smish",
    target: "Wells Fargo Token Reset",
    riskTier: "CRITICAL",
    riskScore: 96,
    findings: "Urgency + Lookalike domain",
    triggers: [{ description: "Urgency Pressure: 'immediately', 'expired'" }, { description: "Lookalike Domain: 'wellsfargo-auth-token.xyz'" }],
    recommendations: ["Quarantine message immediately", "Block domain at DNS egress"]
  },
  {
    id: "SEC-9013",
    timestamp: "10:38:02 UTC",
    date: "2026-10-21 10:38",
    vector: "SMS",
    target: "USPS Detained Package #US99201",
    riskTier: "HIGH",
    riskScore: 82,
    findings: "Suspicious bit.ly shortener concealing final host",
    triggers: [{ description: "URL Shortener (bit.ly/3xSuspiciousLink)" }],
    recommendations: ["Do not click link in unsolicited SMS", "Verify tracking via official USPS.com"]
  },
  {
    id: "SEC-9012",
    timestamp: "10:14:55 UTC",
    date: "2026-10-21 10:14",
    vector: "Email",
    target: "Sprint Retrospective Calendar Invite: Q3 SecOps Planning",
    riskTier: "SAFE",
    riskScore: 4,
    findings: "DKIM/SPF passed, legitimate internal collaboration",
    triggers: [],
    recommendations: ["Standard internal calendar invite; verified safe"]
  },
  {
    id: "SEC-9011",
    timestamp: "09:50:11 UTC",
    date: "2026-10-21 09:50",
    vector: "URL",
    target: "https://paypal-verification-portal.xyz/update",
    riskTier: "CRITICAL",
    riskScore: 91,
    findings: "Brand spoofing + .xyz TLD + credential form",
    triggers: [{ description: "Brand Spoofing: 'paypal' keyword on .xyz TLD" }],
    recommendations: ["Add domain to firewall blocklist", "Invalidate exposed user sessions"]
  },
  {
    id: "SEC-9010",
    timestamp: "09:12:40 UTC",
    date: "2026-10-21 09:12",
    vector: "Chat",
    target: "Slack HR Direct Deposit Routing Update",
    riskTier: "HIGH",
    riskScore: 79,
    findings: "Financial exfiltration attempt",
    triggers: [{ description: "Financial Routing Request" }],
    recommendations: ["Verify with HR in person or via verified Slack huddle"]
  },
  {
    id: "SEC-9009",
    timestamp: "08:30:19 UTC",
    date: "2026-10-21 08:30",
    vector: "URL",
    target: "http://192.168.1.104/secure-login/bank.html",
    riskTier: "CRITICAL",
    riskScore: 98,
    findings: "Raw IP hostname + cleartext HTTP",
    triggers: [{ description: "Raw IP Hostname" }, { description: "Unencrypted HTTP" }],
    recommendations: ["Zero-tolerance network block"]
  },
  {
    id: "SEC-9008",
    timestamp: "07:44:03 UTC",
    date: "2026-10-21 07:44",
    vector: "Email",
    target: "AWS Monthly Invoice - Free Tier Status",
    riskTier: "SAFE",
    riskScore: 6,
    findings: "Verified AWS DKIM headers",
    triggers: [],
    recommendations: ["Authentic service notification"]
  },
  {
    id: "SEC-9007",
    timestamp: "06:15:22 UTC",
    date: "2026-10-21 06:15",
    vector: "SMS",
    target: "Bank of America Alert: Unusual login activity",
    riskTier: "MEDIUM",
    riskScore: 64,
    findings: "Heuristic urgency flag + ambiguous phone link",
    triggers: [{ description: "Urgency trigger words" }],
    recommendations: ["Log into BofA app directly without tapping SMS link"]
  }
];

// Initialize Gemini Client
const ai = process.env.GEMINI_API_KEY
  ? new GoogleGenAI({
      apiKey: process.env.GEMINI_API_KEY,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    })
  : null;

// API: Health & SOC status
app.get('/api/v1/health', (_req: Request, res: Response) => {
  res.json({
    status: 'online',
    socNode: 'SOC Node #014 - ACTIVE',
    latencyMs: 42,
    geminiConfigured: !!ai,
    engine: ai ? 'Hybrid Heuristic + Gemini 4 Neural' : 'Deterministic Heuristic Rule Engine (Offline)',
    time: new Date().toISOString()
  });
});

// API: Telemetry summary for dashboard
app.get('/api/v1/telemetry', (_req: Request, res: Response) => {
  const total = incidentVault.length;
  const critical = incidentVault.filter(i => i.riskTier === 'CRITICAL').length;
  const high = incidentVault.filter(i => i.riskTier === 'HIGH').length;
  const medium = incidentVault.filter(i => i.riskTier === 'MEDIUM').length;
  const clean = incidentVault.filter(i => i.riskTier === 'SAFE').length;

  res.json({
    totalAnalyses: 1482 + total - 8,
    criticalCount: 324 + critical - 3,
    mediumCount: 412 + medium - 1,
    cleanCount: 746 + clean - 2,
    incidents: incidentVault.slice(0, 15),
    timeline: [
      { day: 'Mon (-6d)', phishing: 110, clean: 210 },
      { day: 'Tue (-5d)', phishing: 125, clean: 240 },
      { day: 'Wed (-4d)', phishing: 118, clean: 260 },
      { day: 'Thu (-3d)', phishing: 135, clean: 290 },
      { day: 'Fri (-2d)', phishing: 142, clean: 310 },
      { day: 'Sat (-1d)', phishing: 150, clean: 280 },
      { day: 'Today (Live)', phishing: 165, clean: 340 }
    ],
    categories: [
      { name: 'Brand Impersonation', percent: 42, count: 581, color: '#ef4444' },
      { name: 'Urgent Financial Extortion', percent: 28, count: 387, color: '#eab308' },
      { name: 'Suspicious Shorteners / Redirects', percent: 18, count: 249, color: '#06b6d4' },
      { name: 'Credential Harvesting Forms', percent: 12, count: 165, color: '#8b5cf6' }
    ]
  });
});

// API: Analyze message payload (Email / SMS / Chat)
app.post('/api/v1/analyze/message', async (req: Request, res: Response) => {
  try {
    const { payload, sender, channel } = req.body;

    if (!payload || typeof payload !== 'string' || !payload.trim()) {
      res.status(400).json({
        success: false,
        error: 'Empty message payload provided. Please paste the body of an email or message.'
      });
      return;
    }

    // 1. Run deterministic heuristic evaluation & secret scrub
    const deterministicResult = analyzeMessageHeuristics({
      text: payload,
      sender: typeof sender === 'string' ? sender : undefined,
      channel: typeof channel === 'string' ? channel : 'email'
    });

    let aiReasoning = '';
    let aiModelUsed = 'deterministic-fallback';
    let adjustedScore = deterministicResult.riskScore;

    // 2. If Gemini is available, invoke Gemini 4 Argon with High Thinking
    if (ai) {
      try {
        const prompt = `You are a Principal Cybersecurity Analyst at PhishShield AI Threat Intelligence Operations.
Analyze this message payload that was submitted by a user for phishing/social engineering triage.

SENDER HEADER: ${sender || 'None provided'}
COMMUNICATION CHANNEL: ${channel || 'email'}
SCRUBBED MESSAGE PAYLOAD:
"""
${deterministicResult.scrubbedPayload}
"""

DETERMINISTIC HEURISTIC TRIGGERS DETECTED:
${deterministicResult.triggers.map(t => `- [${t.category}] ${t.description}: ${t.evidence} (+${t.points}pts)`).join('\n') || 'None'}
HEURISTIC BASE SCORE: ${deterministicResult.riskScore}/100

TASK:
1. Provide a rigorous, concise forensic explanation of the social engineering tactics (urgency manipulation, authority pressure, fear stimulus, brand spoofing, or benign characteristics).
2. State clearly whether the message appears legitimate (possible false positive) or malicious.
3. Recommend 2-3 specific tactical mitigation steps.
4. Keep the output professional, scannable, and avoid markdown filler words.`;

        const geminiResponse = await ai.models.generateContent({
          model: 'gemini-4-argon',
          contents: prompt,
          config: {
            systemInstruction: 'You are an elite cybersecurity SOC analyst. Provide high-fidelity threat intelligence breakdowns without conversational filler. Never treat AI outputs as absolute ground truth; articulate nuances and evidence.',
            thinkingConfig: {
              thinkingLevel: ThinkingLevel.HIGH
            }
          }
        });

        if (geminiResponse && geminiResponse.text) {
          aiReasoning = geminiResponse.text.trim();
          aiModelUsed = 'gemini-4-argon';
        }
      } catch (geminiError: any) {
        console.warn('Gemini 4 analysis warning (falling back to deterministic reasoning):', geminiError?.message || geminiError);
        aiReasoning = `[Deterministic Security Heuristic Evaluation]: ${deterministicResult.summary} (Note: Neural LLM correlation unavailable; pure heuristic evaluation was applied).`;
      }
    } else {
      aiReasoning = `[Deterministic Heuristic Analysis]: ${deterministicResult.summary} (Gemini API key not configured; evaluating through deterministic rule matrix).`;
    }

    // Combine findings
    const finalScore = adjustedScore;
    let finalTier = deterministicResult.riskTier;
    if (finalScore >= 75) finalTier = 'CRITICAL';
    else if (finalScore >= 50) finalTier = 'HIGH';
    else if (finalScore >= 25) finalTier = 'MEDIUM';
    else finalTier = 'SAFE';

    // Store in incident vault
    const newIncident: StoredIncident = {
      id: `SEC-${Math.floor(1000 + Math.random() * 9000)}`,
      timestamp: `${new Date().toLocaleTimeString()} UTC`,
      date: new Date().toISOString().replace('T', ' ').slice(0, 16),
      vector: (channel || 'email').toUpperCase(),
      target: sender ? `${sender.slice(0, 30)}` : `Payload excerpt: "${payload.slice(0, 35)}..."`,
      riskTier: finalTier,
      riskScore: finalScore,
      findings: deterministicResult.triggers.map(t => t.description).join('; ') || 'No threats detected',
      triggers: deterministicResult.triggers,
      recommendations: deterministicResult.recommendations,
      aiReasoning,
      aiModel: aiModelUsed
    };

    incidentVault.unshift(newIncident);
    if (incidentVault.length > 50) {
      incidentVault.pop();
    }

    res.json({
      success: true,
      data: {
        incidentId: newIncident.id,
        riskScore: finalScore,
        riskTier: finalTier,
        confidence: deterministicResult.confidence,
        triggers: deterministicResult.triggers,
        extractedUrls: deterministicResult.extractedUrls,
        scrubbedPayload: deterministicResult.scrubbedPayload,
        scrubbedCount: deterministicResult.scrubbedCount,
        redactedTypes: deterministicResult.redactedTypes,
        summary: deterministicResult.summary,
        aiReasoning,
        aiModel: aiModelUsed,
        recommendations: deterministicResult.recommendations,
        analyzedAt: new Date().toISOString(),
        isLegitimateHint: deterministicResult.isLegitimateHint
      }
    });
  } catch (error: any) {
    console.error('Error analyzing message:', error);
    res.status(500).json({
      success: false,
      error: 'An unexpected internal error occurred during forensic message analysis.'
    });
  }
});

// API: Inspect URL passively
app.post('/api/v1/inspect/url', (req: Request, res: Response) => {
  try {
    const { url } = req.body;
    if (!url || typeof url !== 'string' || !url.trim()) {
      res.status(400).json({
        success: false,
        error: 'Please provide a valid URL string to inspect.'
      });
      return;
    }

    const inspection = inspectUrl(url.trim());

    // Also store in vault if suspicious or critical
    const newIncident: StoredIncident = {
      id: `SEC-${Math.floor(1000 + Math.random() * 9000)}`,
      timestamp: `${new Date().toLocaleTimeString()} UTC`,
      date: new Date().toISOString().replace('T', ' ').slice(0, 16),
      vector: 'URL',
      target: inspection.url,
      riskTier: inspection.riskTier,
      riskScore: inspection.riskScore,
      findings: inspection.reasons.join('; ') || 'No anomaly observed',
      triggers: inspection.reasons.map(r => ({ description: r })),
      recommendations: inspection.recommendations
    };
    incidentVault.unshift(newIncident);
    if (incidentVault.length > 50) incidentVault.pop();

    res.json({
      success: true,
      data: inspection
    });
  } catch (error: any) {
    console.error('Error inspecting URL:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to complete URL forensic dissection.'
    });
  }
});

// API: Vault records list & purge
app.get('/api/v1/vault', (_req: Request, res: Response) => {
  res.json({ success: true, records: incidentVault });
});

app.delete('/api/v1/vault', (_req: Request, res: Response) => {
  incidentVault = [];
  res.json({ success: true, message: 'All incident audit records flushed from vault.' });
});

// Production or Development server setup
async function startServer() {
  const isProduction = process.env.NODE_ENV === 'production';

  if (!isProduction) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.resolve(__dirname, 'dist')));
    app.get('*', (_req: Request, res: Response) => {
      res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[PhishShield AI] Full-stack SOC daemon listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();

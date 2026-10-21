import test from 'node:test';
import assert from 'node:assert/strict';
import {
  scrubSecrets,
  extractUrls,
  inspectUrl,
  analyzeMessageHeuristics
} from '../utils/security-rules.ts';

test('Test Case 1: Empty input returns zero risk score and safe tier', () => {
  const result = analyzeMessageHeuristics({ text: '' });
  assert.equal(result.riskScore, 0);
  assert.equal(result.riskTier, 'SAFE');
  assert.equal(result.triggers.length, 0);
});

test('Test Case 2: Malformed URL parsing returns handled violation without crashing', () => {
  const result = inspectUrl('://broken-bad-scheme');
  assert.equal(result.isValid, false);
  assert.ok(result.riskScore > 50);
  assert.equal(result.riskTier, 'HIGH');
});

test('Test Case 3: Legitimate calendar invite receives low score and SAFE tier (no false positive)', () => {
  const result = analyzeMessageHeuristics({
    text: 'Hi Alex, sharing the Google Meet link for our team sprint retrospective and internal planning meeting tomorrow at 2pm. Confluence doc is updated.',
    sender: 'alex.turner@company-internal.org'
  });
  assert.ok(result.riskScore <= 20, `Expected low score, got ${result.riskScore}`);
  assert.equal(result.riskTier, 'SAFE');
  assert.equal(result.isLegitimateHint, true);
});

test('Test Case 4: High-urgency financial extortion triggers CRITICAL risk tier', () => {
  const result = analyzeMessageHeuristics({
    text: 'URGENT: Your Chase checking account access has been suspended immediately. Confirm credentials within 24 hours. Provide your password and 6-digit OTP code at http://chase-security-verify.xyz',
    sender: 'security@chase-resolution-portal.ru'
  });
  assert.ok(result.riskScore >= 75, `Expected critical score >= 75, got ${result.riskScore}`);
  assert.equal(result.riskTier, 'CRITICAL');
  assert.ok(result.triggers.some(t => t.category === 'URGENCY'));
  assert.ok(result.triggers.some(t => t.category === 'CREDENTIAL_HARVEST'));
});

test('Test Case 5: Extracts multiple distinct URLs accurately', () => {
  const text = 'Check out https://paypal-verification.xyz/login and also http://192.168.1.50/admin and https://google.com';
  const urls = extractUrls(text);
  assert.equal(urls.length, 3);
  assert.ok(urls.includes('https://paypal-verification.xyz/login'));
  assert.ok(urls.includes('http://192.168.1.50/admin'));
  assert.ok(urls.includes('https://google.com'));
});

test('Test Case 6: Handles extreme length payload without memory or performance breakdown', () => {
  const longPayload = 'Normal communication line with benign remarks.\n'.repeat(500);
  const result = analyzeMessageHeuristics({ text: longPayload });
  assert.ok(result.riskScore >= 0 && result.riskScore <= 100);
  assert.equal(result.riskTier, 'SAFE');
});

test('Test Case 7: PII & sensitive secrets (passwords, OTPs, SSNs) are scrubbed before storage/egress', () => {
  const secretText = 'Here is your OTP code: 894102 and my password: SuperSecret123! and SSN: 123-45-6789';
  const scrubbed = scrubSecrets(secretText);
  assert.equal(scrubbed.scrubbedCount, 3);
  assert.ok(!scrubbed.sanitized.includes('894102'));
  assert.ok(!scrubbed.sanitized.includes('SuperSecret123!'));
  assert.ok(!scrubbed.sanitized.includes('123-45-6789'));
  assert.ok(scrubbed.sanitized.includes('[SECRET SCRUBBED: OTP 6-digit]'));
});

test('Test Case 8: Raw IP address hostname in URL flagged as critical danger', () => {
  const urlRes = inspectUrl('http://194.26.29.112/secure-login/bank.html');
  assert.equal(urlRes.isIpAddress, true);
  assert.equal(urlRes.isHttps, false);
  assert.ok(urlRes.riskScore >= 75);
  assert.equal(urlRes.riskTier, 'CRITICAL');
});

test('Test Case 9: Brand typosquatting/homograph impersonation detected on non-authorized domains', () => {
  const urlRes = inspectUrl('https://paypal-security-verification.xyz/update-token');
  assert.equal(urlRes.hasBrandSpoofing, true);
  assert.equal(urlRes.spoofedBrand, 'paypal');
  assert.equal(urlRes.isSuspiciousTld, true);
  assert.ok(urlRes.riskScore >= 75);
  assert.equal(urlRes.riskTier, 'CRITICAL');
});

test('Test Case 10: Strict mathematical invariant holds: 0 <= score <= 100 across varied scenarios', () => {
  const scenarios = [
    '',
    'Clean message',
    'URGENT URGENT URGENT password pin otp ssn wire transfer bitcoin http://bad.xyz http://1.1.1.1',
    'Very mild note with bit.ly/test link'
  ];
  for (const s of scenarios) {
    const res = analyzeMessageHeuristics({ text: s });
    assert.ok(res.riskScore >= 0, `Score below 0: ${res.riskScore}`);
    assert.ok(res.riskScore <= 100, `Score above 100: ${res.riskScore}`);
  }
});

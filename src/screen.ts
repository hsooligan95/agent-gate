/**
 * Output screening: scan upstream tool results before they reach the agent.
 *
 * Two classes of findings:
 *  - prompt injection: text in tool output that tries to steer the agent
 *    ("ignore previous instructions", "export all data", fake system turns...)
 *  - PII / secrets: SSNs, card numbers, emails, phone numbers, AWS-style
 *    access keys, private-key blocks. PII values are redacted in place.
 *
 * This is a reference implementation: pattern-based screening is a seatbelt,
 * not a proof of safety. It raises the cost of the classic attacks and, just
 * as importantly, makes them visible in the audit log.
 */

export interface Finding {
  kind: "injection" | "pii";
  pattern: string;
  excerpt: string;
}

const INJECTION_PATTERNS: Array<{ name: string; re: RegExp }> = [
  { name: "ignore-instructions", re: /ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules)/i },
  { name: "disregard-instructions", re: /disregard\s+(all\s+)?(previous|prior|your)\s+(instructions|rules|training)/i },
  { name: "export-all-data", re: /(export|send|upload|forward|exfiltrate)\s+(all\s+)?(the\s+)?(data|files|records|credentials|secrets)/i },
  { name: "fake-system-turn", re: /(^|\n)\s*(system\s*:|<\s*system\s*>|\[system\])/i },
  { name: "new-instructions", re: /your\s+(new\s+)?(instructions|task|orders)\s+(are|is)\s*:/i },
  { name: "reveal-system-prompt", re: /(reveal|print|repeat|show)\s+(your\s+)?(system\s+prompt|instructions|prompt)/i },
  { name: "role-override", re: /you\s+are\s+now\s+(a|an|in)\b/i },
  { name: "secret-exfil-url", re: /https?:\/\/[^\s"']+\?[^\s"']*(token|key|secret|data)=/i },
];

const PII_PATTERNS: Array<{ name: string; re: RegExp; replacement: string }> = [
  { name: "ssn", re: /\b\d{3}-\d{2}-\d{4}\b/g, replacement: "[REDACTED:SSN]" },
  { name: "credit-card", re: /\b(?:\d{4}[- ]){3}\d{4}\b/g, replacement: "[REDACTED:CARD]" },
  { name: "aws-access-key", re: /\bAKIA[0-9A-Z]{16}\b/g, replacement: "[REDACTED:AWS-KEY]" },
  { name: "private-key", re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, replacement: "[REDACTED:PRIVATE-KEY]" },
  { name: "email", re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, replacement: "[REDACTED:EMAIL]" },
  { name: "phone", re: /\b(?:\+1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}\b/g, replacement: "[REDACTED:PHONE]" },
];

export interface ScreenResult {
  text: string;
  findings: Finding[];
  /** PII-redacted copy of the input (injection text is left in place; see screenText caller policy). */
  redacted: string;
}

function excerpt(text: string, index: number, match: string): string {
  const start = Math.max(0, index - 20);
  const end = Math.min(text.length, index + match.length + 20);
  return text.slice(start, end).replace(/\s+/g, " ").trim();
}

export function screenText(text: string): ScreenResult {
  const findings: Finding[] = [];
  for (const { name, re } of INJECTION_PATTERNS) {
    const m = re.exec(text);
    if (m) findings.push({ kind: "injection", pattern: name, excerpt: excerpt(text, m.index, m[0]) });
  }
  let redacted = text;
  for (const { name, re, replacement } of PII_PATTERNS) {
    for (const m of text.matchAll(re)) {
      findings.push({ kind: "pii", pattern: name, excerpt: excerpt(text, m.index ?? 0, m[0]) });
    }
    redacted = redacted.replace(re, replacement);
  }
  return { text, findings, redacted };
}

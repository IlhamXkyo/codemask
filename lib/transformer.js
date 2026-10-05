import crypto from 'node:crypto';
import { scanForSecrets, RULE_DEFINITIONS } from './detector.js';

function generateShortHash(value) {
  return crypto.createHash('sha256').update(value).digest('hex').substring(0, 8);
}

export function maskContent(content, existingMapping = {}) {
  const findings = scanForSecrets(content);
  const mapping = { ...existingMapping };
  const reverseLookup = new Map();

  for (const [token, secret] of Object.entries(mapping)) {
    reverseLookup.set(secret, token);
  }

  // Pre-generate tokens for all unique secrets
  const ruleMap = new Map(RULE_DEFINITIONS.map(r => [r.id, r]));

  for (const finding of findings) {
    const raw = finding.rawSecret;
    if (!reverseLookup.has(raw)) {
      const rule = ruleMap.get(finding.ruleId);
      const hash = generateShortHash(raw);
      let placeholder;

      if (rule && rule.placeholderPrefix.includes('MASKED_')) {
        if (rule.id === 'private_key_block') {
          placeholder = `-----BEGIN RSA PRIVATE KEY-----\nMASKED_PRIVATE_KEY_BLOCK_${hash}\n-----END RSA PRIVATE KEY-----`;
        } else if (rule.id === 'db_connection_url') {
          placeholder = `postgresql://user_${hash}:pass_${hash}@cluster_${hash}.internal/appdb`;
        } else {
          placeholder = `${rule.placeholderPrefix}${hash}`;
        }
      } else {
        placeholder = `MASKED_VAL_${hash}`;
      }

      mapping[placeholder] = raw;
      reverseLookup.set(raw, placeholder);
    }
  }

  // Replace secrets with placeholders in content
  // We sort unique secrets by length descending to prevent partial prefix replacement issues
  const uniqueSecrets = Array.from(reverseLookup.keys()).sort((a, b) => b.length - a.length);

  let maskedContent = content;
  for (const secret of uniqueSecrets) {
    const placeholder = reverseLookup.get(secret);
    maskedContent = maskedContent.split(secret).join(placeholder);
  }

  return {
    maskedContent,
    mapping,
    findingsCount: findings.length,
    uniqueCount: Object.keys(mapping).length,
  };
}

export function unmaskContent(content, mapping) {
  if (!mapping || Object.keys(mapping).length === 0) {
    return {
      unmaskedContent: content,
      restoredCount: 0,
    };
  }

  // Sort placeholders by length descending
  const placeholders = Object.keys(mapping).sort((a, b) => b.length - a.length);
  let unmaskedContent = content;
  let restoredCount = 0;

  for (const placeholder of placeholders) {
    const original = mapping[placeholder];
    if (unmaskedContent.includes(placeholder)) {
      const occurrences = unmaskedContent.split(placeholder).length - 1;
      restoredCount += occurrences;
      unmaskedContent = unmaskedContent.split(placeholder).join(original);
    }
  }

  return {
    unmaskedContent,
    restoredCount,
  };
}

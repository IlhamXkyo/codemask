import crypto from 'node:crypto';
import { scanForSecrets, RULE_DEFINITIONS } from './detector.js';

function generateShortHash(value) {
  return crypto.createHash('sha256').update(value).digest('hex').substring(0, 8);
}

export function detectLingeringPlaceholders(content) {
  const pattern = /\b(?:sk-(?:proj-)?MASKED_[A-Za-z0-9_-]+|sk-ant-MASKED_[A-Za-z0-9_-]+|github_pat_MASKED_[A-Za-z0-9_]+|ghp_MASKED_[A-Za-z0-9_]+|hf_MASKED_[A-Za-z0-9_]+|npm_MASKED_[A-Za-z0-9_]+|glpat-MASKED_[A-Za-z0-9_-]+|eyJ_MASKED_[A-Za-z0-9_]+|AKIA_MASKED_[A-Za-z0-9_]+|sk_live_MASKED_[A-Za-z0-9_]+|AIza_MASKED_[A-Za-z0-9_]+|xoxb_MASKED_[A-Za-z0-9_]+|MASKED_[A-Za-z0-9_]+)\b/g;
  const matches = content.match(pattern);
  return matches ? Array.from(new Set(matches)) : [];
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

      if (rule && rule.placeholderPrefix && rule.placeholderPrefix.includes('MASKED_')) {
        if (rule.id === 'private_key_block') {
          placeholder = `-----BEGIN RSA PRIVATE KEY-----\nMASKED_PRIVATE_KEY_BLOCK_${hash}\n-----END RSA PRIVATE KEY-----`;
        } else if (rule.id === 'db_connection_url') {
          placeholder = `postgresql://user_${hash}:pass_${hash}@cluster_${hash}.internal/appdb`;
        } else if (rule.id === 'local_user_path_win') {
          const sep = raw.includes('\\\\') ? '\\\\' : '\\';
          const drive = raw.slice(0, 2);
          placeholder = `${drive}${sep}Users${sep}MASKED_DEV_USER_${hash}`;
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
  // Sort unique secrets by length descending to prevent partial prefix replacement issues
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

export function unmaskContent(content, mapping = {}) {
  if (!mapping || Object.keys(mapping).length === 0) {
    const unmatched = detectLingeringPlaceholders(content);
    return {
      unmaskedContent: content,
      restoredCount: 0,
      unmatchedPlaceholders: unmatched,
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

  const unmatchedPlaceholders = detectLingeringPlaceholders(unmaskedContent);

  return {
    unmaskedContent,
    restoredCount,
    unmatchedPlaceholders,
  };
}

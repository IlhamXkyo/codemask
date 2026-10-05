export function calculateEntropy(str) {
  if (!str || str.length === 0) return 0;
  const frequencies = {};
  for (const ch of str) {
    frequencies[ch] = (frequencies[ch] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(frequencies)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export const RULE_DEFINITIONS = [
  {
    id: 'openai_api_key',
    name: 'OpenAI API Key',
    priority: 10,
    regex: /\b(sk-(?:proj-)?[A-Za-z0-9_-]{32,80})\b/g,
    placeholderPrefix: 'sk-proj-MASKED_OPENAI_',
    category: 'api_key',
  },
  {
    id: 'anthropic_api_key',
    name: 'Anthropic API Key',
    priority: 10,
    regex: /\b(sk-ant-api\d{2}-[a-zA-Z0-9_\-]{80,110})\b/g,
    placeholderPrefix: 'sk-ant-MASKED_ANTHROPIC_',
    category: 'api_key',
  },
  {
    id: 'github_token',
    name: 'GitHub Token',
    priority: 10,
    regex: /\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b/g,
    placeholderPrefix: 'ghp_MASKED_GITHUB_TOKEN_',
    category: 'api_key',
  },
  {
    id: 'aws_access_key',
    name: 'AWS Access Key ID',
    priority: 10,
    regex: /\b(AKIA[0-9A-Z]{16})\b/g,
    placeholderPrefix: 'AKIA_MASKED_AWS_KEY_',
    category: 'credential',
  },
  {
    id: 'stripe_key',
    name: 'Stripe API Key',
    priority: 10,
    regex: /\b((?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,60})\b/g,
    placeholderPrefix: 'sk_live_MASKED_STRIPE_',
    category: 'api_key',
  },
  {
    id: 'google_api_key',
    name: 'Google API Key',
    priority: 10,
    regex: /\b(AIza[0-9A-Za-z\-_]{35})\b/g,
    placeholderPrefix: 'AIza_MASKED_GOOGLE_KEY_',
    category: 'api_key',
  },
  {
    id: 'slack_token',
    name: 'Slack Token',
    priority: 10,
    regex: /\b(xox[baprs]-[0-9]{10,14}-[0-9]{10,14}-[a-zA-Z0-9]{24,34})\b/g,
    placeholderPrefix: 'xoxb_MASKED_SLACK_TOKEN_',
    category: 'api_key',
  },
  {
    id: 'db_connection_url',
    name: 'Database Connection String',
    priority: 10,
    regex: /\b((?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|amqp|amqps):\/\/[^:\/\s]+:[^@\s]+@[^:\/\s]+(?::\d+)?(?:\/[^\s"']*)?)\b/g,
    placeholderPrefix: 'postgresql://user_masked:pass_masked@db_host_masked.internal/',
    category: 'database',
  },
  {
    id: 'private_key_block',
    name: 'Private Key PEM Block',
    priority: 10,
    regex: /(-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----)/g,
    placeholderPrefix: '-----BEGIN RSA PRIVATE KEY-----\nMASKED_PRIVATE_KEY_BLOCK\n-----END RSA PRIVATE KEY-----',
    category: 'crypto_key',
  },
  {
    id: 'bearer_token',
    name: 'Authorization Bearer Header',
    priority: 8,
    regex: /(Bearer\s+)([A-Za-z0-9.\-_~+/]+=*)/g,
    customExtractor: (match, group1, group2) => {
      if (group2.length >= 20 && calculateEntropy(group2) >= 3.0) {
        return {
          raw: group2,
          prefix: group1,
        };
      }
      return null;
    },
    placeholderPrefix: 'MASKED_BEARER_TOKEN_',
    category: 'auth_header',
  },
  {
    id: 'assigned_secret',
    name: 'Generic Assigned High-Entropy Secret',
    priority: 3,
    regex: /(?:const|let|var|apiKey|api_key|token|secret|password|passwd|auth_token)\s*[:=]\s*["']([^"']{16,128})["']/gi,
    customExtractor: (match, group1) => {
      if (calculateEntropy(group1) >= 3.6) {
        return {
          raw: group1,
          offsetInMatch: match[0].lastIndexOf(group1),
        };
      }
      return null;
    },
    placeholderPrefix: 'MASKED_SECRET_STRING_',
    category: 'generic_secret',
  },
  {
    id: 'local_user_path_win',
    name: 'Windows User Profile Path',
    priority: 2,
    regex: /([A-Za-z]:(?:\\\\|\\)Users(?:\\\\|\\)([A-Za-z0-9_.\-]+))/g,
    customExtractor: (match, fullPath, username) => {
      const ignored = ['Public', 'Default', 'All Users'];
      if (ignored.includes(username)) return null;
      return {
        raw: fullPath,
        offsetInMatch: 0,
      };
    },
    placeholderPrefix: 'C:\\Users\\DEV_USER',
    category: 'filesystem_path',
  },
  {
    id: 'local_user_path_unix',
    name: 'Unix Home Directory Path',
    priority: 2,
    regex: /(\/(?:home|Users)\/([A-Za-z0-9_.\-]+))/g,
    customExtractor: (match, fullPath, username) => {
      const ignored = ['shared', 'public', 'daemon'];
      if (ignored.includes(username)) return null;
      return {
        raw: fullPath,
        offsetInMatch: 0,
      };
    },
    placeholderPrefix: '/home/dev_user',
    category: 'filesystem_path',
  },
];

export function scanForSecrets(content) {
  const matches = [];

  for (const rule of RULE_DEFINITIONS) {
    const rx = new RegExp(rule.regex);
    let match;

    while ((match = rx.exec(content)) !== null) {
      if (rule.customExtractor) {
        const extracted = rule.customExtractor(match, match[1], match[2]);
        if (extracted && extracted.raw) {
          const offset = extracted.offsetInMatch !== undefined
            ? extracted.offsetInMatch
            : (extracted.prefix ? extracted.prefix.length : 0);
          const startIndex = match.index + offset;
          matches.push({
            ruleId: rule.id,
            ruleName: rule.name,
            category: rule.category,
            priority: rule.priority,
            rawSecret: extracted.raw,
            startIndex,
            endIndex: startIndex + extracted.raw.length,
          });
        }
      } else {
        const rawSecret = match[1] || match[0];
        const offset = match[0].indexOf(rawSecret);
        const startIndex = match.index + (offset >= 0 ? offset : 0);
        matches.push({
          ruleId: rule.id,
          ruleName: rule.name,
          category: rule.category,
          priority: rule.priority,
          rawSecret,
          startIndex,
          endIndex: startIndex + rawSecret.length,
        });
      }
    }
  }

  // Sort by priority descending first, then by start position
  matches.sort((a, b) => {
    if (b.priority !== a.priority) {
      return b.priority - a.priority;
    }
    return a.startIndex - b.startIndex;
  });

  // Filter overlapping ranges, favoring higher priority
  const selected = [];

  for (const candidate of matches) {
    const hasOverlap = selected.some(s =>
      Math.max(s.startIndex, candidate.startIndex) < Math.min(s.endIndex, candidate.endIndex)
    );
    if (!hasOverlap) {
      selected.push(candidate);
    }
  }

  selected.sort((a, b) => a.startIndex - b.startIndex);
  return selected;
}

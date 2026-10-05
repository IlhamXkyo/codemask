# codemask

> Zero-dependency reversible secret masking for LLM code workflows and agent prompts.

[![Test](https://img.shields.io/badge/tests-passing-brightgreen.svg)](file:///test)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](file:///LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18.0.0-blue.svg)](https://nodejs.org)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-success.svg)](file:///package.json)

When developers feed code to LLMs (Claude, ChatGPT, Cursor, Copilot), proprietary secrets frequently leak into prompt history: API keys, database connection strings, auth headers, and local home directory paths.

Traditional redaction tools replace sensitive data with `[REDACTED]`, which breaks syntax. When the LLM outputs refactored code or patches containing `[REDACTED]`, the code fails to compile or run, requiring manual copy-paste restoration.

`codemask` solves this bidirectional problem. It replaces secrets with syntax-preserving dummy tokens before sending them to the LLM, tracks the mapping in an encrypted local session, and restores the original secrets seamlessly when the LLM response returns.

---

## Quickstart (30 Seconds)

### Installation

No external dependencies required. Works natively on Node.js 18+.

```bash
# Clone and link locally
git clone https://github.com/IlhamXkyo/codemask.git
cd codemask
npm link
```

### Basic Workflow

```bash
# 1. Mask secrets from your file and pipe directly to your prompt or file
cat src/config.ts | codemask mask > prompt.txt

# 2. After LLM generates updated code into response.ts, restore real secrets
cat response.ts | codemask unmask > src/config.ts

# 3. Clean up the local session mapping
codemask clean
```

---

## Core Features

- **Bidirectional Roundtrip**: Mask before LLM ingestion, unmask upon receiving output without diff conflicts.
- **Syntax Preservation**: Replaces values with format-compatible tokens (e.g., `postgresql://user_masked:pass_masked@...`) so parsers, typecheckers, and LLMs maintain valid ASTs.
- **Zero Dependencies**: Pure Node.js standard library (`node:crypto`, `node:fs`, `node:test`).
- **Encrypted Sessions**: Optional AES-256-GCM encryption for the session mapping file using `--passphrase` or `CODEMASK_PASSPHRASE`.
- **High-Entropy Heuristics**: Shannon entropy calculation combined with specific regex patterns to detect custom API tokens while eliminating false positives.
- **Support for Major Secret Formats**:
  - OpenAI API Keys (`sk-...`, `sk-proj-...`)
  - Anthropic API Keys (`sk-ant-...`)
  - GitHub Access Tokens (`ghp_...`, `github_pat_...`)
  - AWS Access Key IDs (`AKIA...`)
  - Stripe Keys (`sk_live_...`, `pk_live_...`)
  - Google API Keys (`AIza...`)
  - Database Connection Strings (`postgresql://`, `mysql://`, `mongodb://`, `redis://`)
  - Private Key PEM Blocks (`-----BEGIN RSA PRIVATE KEY-----`)
  - Bearer Tokens
  - Windows and Unix developer user profile paths

---

## CLI Reference

```
USAGE:
  codemask <command> [file] [options]

COMMANDS:
  mask [file]       Scan and replace secrets with syntax-preserving placeholders
  unmask [file]     Restore original secrets from session mapping
  inspect           View tokens and masked secrets in current session
  clean             Remove current session file

OPTIONS:
  -s, --session     Session map file path (default: .codemask-session.json)
  -o, --out         Target file to write transformed output (default: stdout)
  -p, --passphrase  Passphrase to encrypt/decrypt session mapping file
      --reveal      Reveal unmasked secrets during inspect command
      --stats       Print detection counts to stderr
  -h, --help        Show help message
  -v, --version     Show version number
```

---

## Real World Example

Given `src/server.ts`:

```typescript
const OPENAI_KEY = "sk-proj-abc12345678901234567890123456789012345678";
const DB_URL = "postgresql://postgres:p@ssword123@prod-cluster.internal:5432/db";

export function connect() {
  return init(OPENAI_KEY, DB_URL);
}
```

Running `codemask mask src/server.ts -o prompt.ts`:

```typescript
const OPENAI_KEY = "sk-proj-MASKED_OPENAI_a7f92b41";
const DB_URL = "postgresql://user_masked:pass_masked@cluster_9e1b2a.internal/appdb";

export function connect() {
  return init(OPENAI_KEY, DB_URL);
}
```

The LLM receives valid TypeScript code, generates its changes, and returns the modified file. Running `codemask unmask prompt.ts -o src/server.ts` completely restores `sk-proj-abc123...` and `p@ssword123`.

---

## Testing

Run the native test suite (no external test runner needed):

```bash
npm test
```

---

## License

MIT © IlhamXkyo

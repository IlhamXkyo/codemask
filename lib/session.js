import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

export const DEFAULT_SESSION_FILENAME = '.codemask-session.json';

function deriveKey(passphrase, salt) {
  return crypto.scryptSync(passphrase, salt, 32);
}

export function saveSession(filePath, mapping, passphrase = null) {
  const sessionData = {
    version: '1.0.0',
    createdAt: new Date().toISOString(),
    itemCount: Object.keys(mapping).length,
    mapping,
  };

  let payload;

  if (passphrase) {
    const salt = crypto.randomBytes(16);
    const iv = crypto.randomBytes(12);
    const key = deriveKey(passphrase, salt);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

    const plaintext = JSON.stringify(sessionData);
    let ciphertext = cipher.update(plaintext, 'utf8', 'hex');
    ciphertext += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');

    payload = JSON.stringify({
      encrypted: true,
      salt: salt.toString('hex'),
      iv: iv.toString('hex'),
      authTag,
      data: ciphertext,
    }, null, 2);
  } else {
    payload = JSON.stringify({
      encrypted: false,
      ...sessionData,
    }, null, 2);
  }

  const resolvedPath = path.resolve(filePath);
  fs.writeFileSync(resolvedPath, payload, { mode: 0o600, encoding: 'utf8' });
  return resolvedPath;
}

export function loadSession(filePath, passphrase = null) {
  const resolvedPath = path.resolve(filePath);
  if (!fs.existsSync(resolvedPath)) {
    throw new Error(`Session file not found: ${resolvedPath}`);
  }

  const raw = fs.readFileSync(resolvedPath, 'utf8');
  const parsed = JSON.parse(raw);

  if (parsed.encrypted) {
    if (!passphrase) {
      throw new Error(`Session file is encrypted. Provide passphrase via --passphrase or CODEMASK_PASSPHRASE env var.`);
    }

    const salt = Buffer.from(parsed.salt, 'hex');
    const iv = Buffer.from(parsed.iv, 'hex');
    const authTag = Buffer.from(parsed.authTag, 'hex');
    const key = deriveKey(passphrase, salt);

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(parsed.data, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    const decryptedSession = JSON.parse(decrypted);
    return decryptedSession.mapping;
  }

  return parsed.mapping;
}

export function inspectSession(filePath, passphrase = null, reveal = false) {
  const mapping = loadSession(filePath, passphrase);
  const entries = Object.entries(mapping);

  return entries.map(([placeholder, secret]) => {
    let preview;
    if (reveal) {
      preview = secret;
    } else {
      if (secret.length <= 8) {
        preview = '***';
      } else {
        const head = secret.substring(0, 3);
        const tail = secret.substring(secret.length - 3);
        preview = `${head}...${tail} (${secret.length} chars)`;
      }
    }
    return {
      placeholder,
      preview,
      originalLength: secret.length,
    };
  });
}

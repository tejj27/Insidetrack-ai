/**
 * /api/chat — Anthropic proxy with security hardening
 *
 * Security layers:
 *  1. CORS — only allow known origins (not *)
 *  2. Rate limiting — 20 req / min per IP (in-memory, resets per instance)
 *  3. Input validation — model whitelist, message format, length caps
 *  4. max_tokens cap — never let a client request more than 2500 tokens
 *  5. Sanitised errors — never leak internal details to the client
 */

const ALLOWED_ORIGINS = [
  'https://insidetrack-ai.vercel.app',
  'https://insidetrack.ai',
  'http://localhost:3000',
  'http://localhost:5173',
  'http://127.0.0.1:5500',
];

const ALLOWED_MODELS = [
  'claude-sonnet-4-20250514',
  'claude-haiku-3-5-20241022',
];

const MAX_TOKENS_CAP    = 2500;
const MAX_MESSAGES      = 20;
const MAX_TOTAL_CHARS   = 40000;
const MAX_SYSTEM_CHARS  = 5000;
const RATE_LIMIT_MAX    = 20;
const RATE_LIMIT_WINDOW = 60000; // 1 minute

const rateLimitStore = new Map();

function getClientIP(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return forwarded.split(',')[0].trim();
  return req.socket?.remoteAddress || 'unknown';
}

function checkRateLimit(ip) {
  const now = Date.now();
  let entry = rateLimitStore.get(ip);

  if (!entry || now > entry.resetAt) {
    entry = { count: 0, resetAt: now + RATE_LIMIT_WINDOW };
  }
  entry.count += 1;
  rateLimitStore.set(ip, entry);

  // Prune stale entries when store grows large
  if (rateLimitStore.size > 2000) {
    for (const [key, val] of rateLimitStore) {
      if (now > val.resetAt) rateLimitStore.delete(key);
    }
  }

  return {
    allowed:    entry.count <= RATE_LIMIT_MAX,
    remaining:  Math.max(0, RATE_LIMIT_MAX - entry.count),
    resetAt:    entry.resetAt,
    retryAfter: Math.ceil((entry.resetAt - now) / 1000),
  };
}

export default async function handler(req, res) {

  // 1. CORS — only reflect allowed origins
  const origin = req.headers.origin || '';
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Vary', 'Origin');
  res.setHeader('X-Content-Type-Options', 'nosniff');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  // 2. Rate limiting
  const ip = getClientIP(req);
  const rate = checkRateLimit(ip);
  res.setHeader('X-RateLimit-Limit', RATE_LIMIT_MAX);
  res.setHeader('X-RateLimit-Remaining', rate.remaining);
  res.setHeader('X-RateLimit-Reset', rate.resetAt);

  if (!rate.allowed) {
    res.setHeader('Retry-After', rate.retryAfter);
    return res.status(429).json({
      error: `Too many requests. Please wait ${rate.retryAfter} seconds and try again.`,
    });
  }

  // 3. Body check
  const body = req.body;
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return res.status(400).json({ error: 'Invalid request body.' });
  }

  const { model, messages, system, max_tokens } = body;

  // 4. Model whitelist
  if (typeof model !== 'string' || !ALLOWED_MODELS.includes(model)) {
    return res.status(400).json({ error: 'Invalid or unsupported model.' });
  }

  // 5. Validate messages
  if (!Array.isArray(messages) || messages.length === 0) {
    return res.status(400).json({ error: 'messages must be a non-empty array.' });
  }
  if (messages.length > MAX_MESSAGES) {
    return res.status(400).json({ error: `Too many messages (max ${MAX_MESSAGES}).` });
  }

  let totalChars = 0;
  for (let i = 0; i < messages.length; i++) {
    const msg = messages[i];
    if (!msg || typeof msg !== 'object') return res.status(400).json({ error: `Message ${i} is invalid.` });
    if (!['user', 'assistant'].includes(msg.role)) return res.status(400).json({ error: `Message ${i} has invalid role.` });
    if (typeof msg.content !== 'string') return res.status(400).json({ error: `Message ${i} content must be a string.` });
    // Strip null bytes and non-printable control chars (keep \n \r \t)
    msg.content = msg.content.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
    totalChars += msg.content.length;
    if (totalChars > MAX_TOTAL_CHARS) {
      return res.status(400).json({ error: 'Input is too long. Please shorten your text and try again.' });
    }
  }

  // 6. Validate system prompt
  if (system !== undefined) {
    if (typeof system !== 'string') return res.status(400).json({ error: 'system must be a string.' });
    if (system.length > MAX_SYSTEM_CHARS) return res.status(400).json({ error: 'System prompt too long.' });
  }

  // 7. Cap max_tokens — client can request lower, never higher
  const safeMaxTokens = (typeof max_tokens === 'number' && max_tokens > 0)
    ? Math.min(max_tokens, MAX_TOKENS_CAP)
    : 1000;

  // 8. Build clean request — only known fields, no arbitrary passthrough
  const cleanBody = {
    model,
    messages: messages.map(m => ({ role: m.role, content: m.content })),
    max_tokens: safeMaxTokens,
    ...(system ? { system: system.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '') } : {}),
  };

  // 9. Call Anthropic
  try {
    const upstream = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify(cleanBody),
    });

    const data = await upstream.json();

    if (!upstream.ok) {
      const status = upstream.status;
      // Log server-side only, never expose upstream details to client
      console.error(`Anthropic error ${status}:`, JSON.stringify(data).slice(0, 200));
      if (status === 429) return res.status(429).json({ error: 'AI service is busy. Please try again in a moment.' });
      if (status === 401 || status === 403) return res.status(500).json({ error: 'Service configuration error. Please contact support.' });
      if (status === 400) return res.status(400).json({ error: 'Request could not be processed. Please shorten your input and try again.' });
      return res.status(500).json({ error: 'AI service error. Please try again.' });
    }

    return res.status(200).json(data);

  } catch (err) {
    console.error('Chat proxy error:', err.message);
    return res.status(500).json({ error: 'Service temporarily unavailable. Please try again.' });
  }
}

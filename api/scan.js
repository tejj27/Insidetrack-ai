/**
 * /api/scan — Server-side scan gate
 *
 * Actions:
 *   check_and_increment  — validate JWT, atomically check limit + increment in DB
 *   migrate_guest        — on sign-in/up: bump scans_used to max(current, guestCount)
 *
 * Why server-side?
 *   Client-side checks can be bypassed by intercepting/spoofing Supabase responses.
 *   This endpoint uses the service-role key (never exposed to the browser) and calls
 *   a SECURITY DEFINER Postgres function for atomic check+increment with no race window.
 *
 * Required Vercel env vars:
 *   SUPABASE_URL          — your Supabase project URL
 *   SUPABASE_SERVICE_KEY  — service-role key (Settings > API in Supabase dashboard)
 *                           ⚠️  Never expose this to the browser
 *
 * Required Supabase SQL (run once in SQL Editor — see README):
 *   increment_scan_if_under_limit(p_user_id uuid, p_limit int) → json
 *   migrate_guest_scans(p_user_id uuid, p_guest_count int) → void
 */

const SUPA_URL          = process.env.SUPABASE_URL || 'https://kknzvaayyihfzkaezhft.supabase.co';
const SUPA_SERVICE_KEY  = process.env.SUPABASE_SERVICE_KEY;
const FREE_SCAN_LIMIT   = 3;

// ── Allowed origins (same list as chat.js) ───────────────────────────────────
const ALLOWED_ORIGINS = [
  'https://insidetrack-ai.vercel.app',
  'https://insidetrack.site',
  'https://insidetrack.ai',
  'http://localhost:3000',
  'http://localhost:5173',
  'http://127.0.0.1:5500',
];

// ── Rate limiting ────────────────────────────────────────────────────────────
const rateLimitStore    = new Map();
const RATE_LIMIT_MAX    = 30;     // scan checks per minute per IP
const RATE_LIMIT_WINDOW = 60000;

function getClientIP(req) {
  const fwd = req.headers['x-forwarded-for'];
  return fwd ? fwd.split(',')[0].trim() : (req.socket?.remoteAddress || 'unknown');
}

function checkRateLimit(ip) {
  const now = Date.now();
  let e = rateLimitStore.get(ip);
  if (!e || now > e.resetAt) e = { count: 0, resetAt: now + RATE_LIMIT_WINDOW };
  e.count++;
  rateLimitStore.set(ip, e);
  if (rateLimitStore.size > 2000) {
    for (const [k, v] of rateLimitStore) if (now > v.resetAt) rateLimitStore.delete(k);
  }
  return { allowed: e.count <= RATE_LIMIT_MAX, retryAfter: Math.ceil((e.resetAt - now) / 1000) };
}

// ── Supabase helpers (service-role key — server only) ────────────────────────
const SERVICE_HEADERS = () => ({
  'apikey':        SUPA_SERVICE_KEY,
  'Authorization': 'Bearer ' + SUPA_SERVICE_KEY,
  'Content-Type':  'application/json',
});

/**
 * Validate a user JWT by calling Supabase /auth/v1/user.
 * Returns the user object, or null if invalid.
 */
async function validateJWT(jwt) {
  try {
    const r = await fetch(SUPA_URL + '/auth/v1/user', {
      headers: {
        'apikey':        SUPA_SERVICE_KEY,
        'Authorization': 'Bearer ' + jwt,
      },
    });
    if (!r.ok) return null;
    const user = await r.json();
    return user && user.id ? user : null;
  } catch {
    return null;
  }
}

/**
 * Call Postgres function: increment_scan_if_under_limit
 * Atomically checks scans_used < limit then increments — no TOCTOU race.
 * Returns { allowed: bool, scans_used: number, plan: string }
 */
async function dbIncrementIfAllowed(userId) {
  const r = await fetch(SUPA_URL + '/rest/v1/rpc/increment_scan_if_under_limit', {
    method:  'POST',
    headers: SERVICE_HEADERS(),
    body:    JSON.stringify({ p_user_id: userId, p_limit: FREE_SCAN_LIMIT }),
  });
  if (!r.ok) {
    const err = await r.text();
    throw new Error('DB increment failed: ' + err.slice(0, 200));
  }
  return r.json(); // { allowed, scans_used, plan }
}

/**
 * Call Postgres function: migrate_guest_scans
 * Sets scans_used = GREATEST(scans_used, guestCount) for the user.
 */
async function dbMigrateGuestScans(userId, guestCount) {
  const r = await fetch(SUPA_URL + '/rest/v1/rpc/migrate_guest_scans', {
    method:  'POST',
    headers: SERVICE_HEADERS(),
    body:    JSON.stringify({ p_user_id: userId, p_guest_count: guestCount }),
  });
  if (!r.ok) {
    const err = await r.text();
    throw new Error('DB migrate failed: ' + err.slice(0, 200));
  }
}

// ── Handler ──────────────────────────────────────────────────────────────────
export default async function handler(req, res) {

  // CORS
  const origin = req.headers.origin || '';
  if (ALLOWED_ORIGINS.includes(origin)) res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Vary', 'Origin');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Cache-Control', 'no-store');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')   return res.status(405).json({ error: 'Method not allowed' });

  // Rate limit
  const ip   = getClientIP(req);
  const rate = checkRateLimit(ip);
  if (!rate.allowed) {
    res.setHeader('Retry-After', rate.retryAfter);
    return res.status(429).json({ error: 'Too many requests. Please wait ' + rate.retryAfter + ' seconds.' });
  }

  // Service key sanity check
  if (!SUPA_SERVICE_KEY) {
    console.error('SUPABASE_SERVICE_KEY env var is not set');
    return res.status(500).json({ error: 'Service configuration error.' });
  }

  // Parse body
  const body = req.body;
  if (!body || typeof body !== 'object') return res.status(400).json({ error: 'Invalid request body.' });

  const { action, guestCount } = body;

  // Extract JWT from Authorization header
  const authHeader = req.headers.authorization || '';
  const jwt = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : null;

  // ── Logged-in user flow ──────────────────────────────────────────────────
  if (jwt) {
    const user = await validateJWT(jwt);
    if (!user) return res.status(401).json({ error: 'Invalid or expired session. Please sign in again.' });

    const userId = user.id;

    if (action === 'check_and_increment') {
      try {
        const result = await dbIncrementIfAllowed(userId);

        if (result.allowed) {
          return res.status(200).json({
            allowed:    true,
            used:       result.scans_used,
            remaining:  result.plan === 'pro' ? 999 : Math.max(0, FREE_SCAN_LIMIT - result.scans_used),
            plan:       result.plan,
          });
        } else {
          return res.status(200).json({
            allowed: false,
            reason:  'limit_reached',
            used:    result.scans_used,
            plan:    result.plan,
          });
        }
      } catch (err) {
        console.error('scan check_and_increment error:', err.message);
        // Fail open so a DB hiccup doesn't block all scans — log and allow
        return res.status(200).json({ allowed: true, used: 0, remaining: FREE_SCAN_LIMIT, plan: 'free', _warn: 'db_error_fail_open' });
      }
    }

    if (action === 'migrate_guest') {
      const count = typeof guestCount === 'number' ? Math.max(0, Math.min(guestCount, FREE_SCAN_LIMIT)) : 0;
      try {
        await dbMigrateGuestScans(userId, count);
        return res.status(200).json({ success: true, migrated: count });
      } catch (err) {
        console.error('scan migrate_guest error:', err.message);
        return res.status(200).json({ success: false }); // non-fatal
      }
    }

    return res.status(400).json({ error: 'Unknown action.' });
  }

  // ── Guest flow ───────────────────────────────────────────────────────────
  // Guest count comes from client localStorage — guests can't truly be blocked
  // server-side without an account, but we respect the honour system + prompt signup
  if (action === 'check_and_increment') {
    const count = typeof guestCount === 'number' ? Math.max(0, guestCount) : 0;
    if (count >= FREE_SCAN_LIMIT) {
      return res.status(200).json({ allowed: false, reason: 'limit_reached', used: count });
    }
    return res.status(200).json({ allowed: true, used: count, remaining: FREE_SCAN_LIMIT - count });
  }

  return res.status(400).json({ error: 'Unknown action.' });
}

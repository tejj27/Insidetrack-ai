/**
 * /api/profile — Secure profile fetch
 *
 * GET /api/profile
 *   Returns { scans_used, plan } for the authenticated user.
 *   Requires:  Authorization: Bearer <supabase-jwt>
 *
 * Why server-side?
 *   The browser was calling Supabase REST directly with the anon key, which
 *   (a) requires permissive RLS rules to work, (b) exposes the table structure,
 *   and (c) was returning 400s when RLS blocked the request.
 *   This endpoint verifies the JWT then reads the profile with the service-role
 *   key — no RLS needed, no credentials exposed to the browser.
 *
 * Required Vercel env vars:
 *   SUPABASE_URL         — your Supabase project URL
 *   SUPABASE_SERVICE_KEY — service-role key (never sent to the browser)
 */

const ALLOWED_ORIGINS = [
  'https://insidetrack-ai.vercel.app',
  'https://insidetrack.ai',
  'http://localhost:3000',
  'http://localhost:5173',
  'http://127.0.0.1:5500',
];

export default async function handler(req, res) {
  // CORS
  const origin = req.headers.origin || '';
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Vary', 'Origin');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  // 1. Extract JWT from Authorization header
  const authHeader = req.headers.authorization || '';
  if (!authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid authorization header.' });
  }
  const jwt = authHeader.slice(7).trim();
  if (!jwt) return res.status(401).json({ error: 'Empty token.' });

  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SERVICE_KEY  = process.env.SUPABASE_SERVICE_KEY;

  if (!SUPABASE_URL || !SERVICE_KEY) {
    console.error('Missing SUPABASE_URL or SUPABASE_SERVICE_KEY env vars');
    return res.status(500).json({ error: 'Service configuration error.' });
  }

  try {
    // 2. Verify the JWT by calling Supabase Auth — this confirms the user is real
    const authRes = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
      headers: {
        'apikey':        SERVICE_KEY,
        'Authorization': `Bearer ${jwt}`,
      },
    });

    if (!authRes.ok) {
      // 401 from Supabase = expired or invalid token
      return res.status(401).json({ error: 'Invalid or expired session. Please sign in again.' });
    }

    const user = await authRes.json();
    const userId = user?.id;
    if (!userId) return res.status(401).json({ error: 'Could not identify user.' });

    // 3. Fetch profile using service-role key (bypasses RLS safely on the server)
    const profileRes = await fetch(
      `${SUPABASE_URL}/rest/v1/profiles?id=eq.${encodeURIComponent(userId)}&select=scans_used,plan,cancel_at_period_end,current_period_end`,
      {
        headers: {
          'apikey':        SERVICE_KEY,
          'Authorization': `Bearer ${SERVICE_KEY}`,
        },
      }
    );

    if (!profileRes.ok) {
      const errText = await profileRes.text();
      console.error('Supabase profile fetch error:', profileRes.status, errText.slice(0, 200));
      return res.status(500).json({ error: 'Could not load profile.' });
    }

    const rows = await profileRes.json();

    // Profile might not exist yet for brand-new users — return safe defaults
    const profile = (rows && rows[0]) ? rows[0] : { scans_used: 0, plan: 'free' };

    return res.status(200).json({
      scans_used:           profile.scans_used ?? 0,
      plan:                 profile.plan ?? 'free',
      cancel_at_period_end: profile.cancel_at_period_end ?? false,
      current_period_end:   profile.current_period_end ?? null,
    });

  } catch (err) {
    console.error('profile endpoint error:', err.message);
    return res.status(500).json({ error: 'Service temporarily unavailable.' });
  }
}

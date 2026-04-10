/**
 * /api/portal — Open the Stripe billing portal
 *
 * POST /api/portal
 *   Requires: Authorization: Bearer <supabase-jwt>
 *   Body:     { returnUrl }
 *   Returns:  { url } — redirect here to manage / cancel subscription
 *
 * Required Vercel env vars:
 *   SUPABASE_URL          — Supabase project URL
 *   SUPABASE_SERVICE_KEY  — service-role key
 *   STRIPE_SECRET_KEY     — Stripe secret key
 */

const ALLOWED_ORIGINS = [
  'https://insidetrack-ai.vercel.app',
  'https://insidetrack.site',
  'https://insidetrack.ai',
  'http://localhost:3000',
  'http://localhost:5173',
  'http://127.0.0.1:5500',
];

export default async function handler(req, res) {
  // ── CORS ──────────────────────────────────────────────────────────────────
  const origin = req.headers.origin || '';
  if (ALLOWED_ORIGINS.includes(origin)) res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Vary', 'Origin');
  res.setHeader('Cache-Control', 'no-store');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')   return res.status(405).json({ error: 'Method not allowed' });

  // ── Env vars ──────────────────────────────────────────────────────────────
  const SUPABASE_URL = process.env.SUPABASE_URL || 'https://kknzvaayyihfzkaezhft.supabase.co';
  const SERVICE_KEY  = process.env.SUPABASE_SERVICE_KEY;
  const STRIPE_KEY   = process.env.STRIPE_SECRET_KEY;

  if (!SUPABASE_URL || !SERVICE_KEY || !STRIPE_KEY) {
    console.error('portal: missing env vars');
    return res.status(500).json({ error: 'Service configuration error.' });
  }

  // ── Validate JWT ──────────────────────────────────────────────────────────
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  const jwt = auth.slice(7).trim();

  const authRes = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
    headers: { apikey: SERVICE_KEY, Authorization: `Bearer ${jwt}` },
  });
  if (!authRes.ok) return res.status(401).json({ error: 'Invalid or expired session.' });

  const user = await authRes.json();
  if (!user?.id) return res.status(401).json({ error: 'Could not identify user.' });

  // ── Get Stripe customer_id from profile ───────────────────────────────────
  const profileRes = await fetch(
    `${SUPABASE_URL}/rest/v1/profiles?id=eq.${encodeURIComponent(user.id)}&select=stripe_customer_id`,
    { headers: { apikey: SERVICE_KEY, Authorization: `Bearer ${SERVICE_KEY}` } }
  );
  const profiles   = await profileRes.json();
  const customerId = profiles?.[0]?.stripe_customer_id;

  if (!customerId) {
    return res.status(400).json({ error: 'No billing account found. Please subscribe first.' });
  }

  // ── Create billing portal session ─────────────────────────────────────────
  const { returnUrl } = req.body || {};

  try {
    const portalRes = await fetch('https://api.stripe.com/v1/billing_portal/sessions', {
      method:  'POST',
      headers: {
        Authorization:  `Bearer ${STRIPE_KEY}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        customer:   customerId,
        return_url: returnUrl || 'https://insidetrack.site',
      }).toString(),
    });

    if (!portalRes.ok) {
      const err = await portalRes.text();
      console.error('Stripe portal error:', err.slice(0, 300));
      return res.status(500).json({ error: 'Could not open billing portal.' });
    }

    const portal = await portalRes.json();
    return res.status(200).json({ url: portal.url });

  } catch (err) {
    console.error('portal error:', err.message);
    return res.status(500).json({ error: 'Service temporarily unavailable.' });
  }
}

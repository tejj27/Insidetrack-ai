/**
 * /api/create-checkout — Create a Stripe Checkout session
 *
 * POST /api/create-checkout
 *   Requires: Authorization: Bearer <supabase-jwt>
 *   Body:     { successUrl, cancelUrl }
 *   Returns:  { url } — redirect here to start payment
 *
 * Flow:
 *   1. Validate JWT
 *   2. Upsert a Stripe Customer (save customer_id to profiles)
 *   3. Create a Checkout session for the monthly subscription
 *   4. Return the hosted Checkout URL
 *
 * Required Vercel env vars:
 *   SUPABASE_URL          — Supabase project URL
 *   SUPABASE_SERVICE_KEY  — service-role key (never sent to browser)
 *   STRIPE_SECRET_KEY     — Stripe secret key  (sk_live_… or sk_test_…)
 *   STRIPE_PRICE_ID       — Price ID of the £4.99/month product (price_…)
 */

const ALLOWED_ORIGINS = [
  'https://insidetrack-ai.vercel.app',
  'https://insidetrack.ai',
  'http://localhost:3000',
  'http://localhost:5173',
  'http://127.0.0.1:5500',
];

export default async function handler(req, res) {
  // ── CORS ─────────────────────────────────────────────────────────────────
  const origin = req.headers.origin || '';
  if (ALLOWED_ORIGINS.includes(origin)) res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Vary', 'Origin');
  res.setHeader('Cache-Control', 'no-store');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')   return res.status(405).json({ error: 'Method not allowed' });

  // ── Env vars ──────────────────────────────────────────────────────────────
  const SUPABASE_URL  = process.env.SUPABASE_URL;
  const SERVICE_KEY   = process.env.SUPABASE_SERVICE_KEY;
  const STRIPE_KEY    = process.env.STRIPE_SECRET_KEY;
  const PRICE_ID      = process.env.STRIPE_PRICE_ID;

  if (!SUPABASE_URL || !SERVICE_KEY || !STRIPE_KEY || !PRICE_ID) {
    console.error('create-checkout: missing env vars');
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

  const userId    = user.id;
  const userEmail = user.email;

  // ── Body ──────────────────────────────────────────────────────────────────
  const { successUrl, cancelUrl } = req.body || {};
  if (!successUrl || !cancelUrl) {
    return res.status(400).json({ error: 'Missing successUrl or cancelUrl.' });
  }

  try {
    // ── Fetch profile ────────────────────────────────────────────────────────
    const profileRes = await fetch(
      `${SUPABASE_URL}/rest/v1/profiles?id=eq.${encodeURIComponent(userId)}&select=plan,stripe_customer_id`,
      { headers: { apikey: SERVICE_KEY, Authorization: `Bearer ${SERVICE_KEY}` } }
    );
    const profiles = await profileRes.json();
    const profile  = profiles?.[0];

    if (profile?.plan === 'pro') {
      return res.status(400).json({ error: 'You are already on the Pro plan.' });
    }

    // ── Upsert Stripe customer ───────────────────────────────────────────────
    let customerId = profile?.stripe_customer_id;

    if (!customerId) {
      const custRes = await fetch('https://api.stripe.com/v1/customers', {
        method:  'POST',
        headers: {
          Authorization:  `Bearer ${STRIPE_KEY}`,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          email:                         userEmail,
          'metadata[supabase_user_id]':  userId,
        }).toString(),
      });

      if (!custRes.ok) {
        const err = await custRes.text();
        console.error('Stripe customer create failed:', err.slice(0, 300));
        return res.status(500).json({ error: 'Could not create payment customer.' });
      }

      const cust = await custRes.json();
      customerId  = cust.id;

      // Persist customer_id in Supabase
      await fetch(
        `${SUPABASE_URL}/rest/v1/profiles?id=eq.${encodeURIComponent(userId)}`,
        {
          method:  'PATCH',
          headers: {
            apikey:          SERVICE_KEY,
            Authorization:   `Bearer ${SERVICE_KEY}`,
            'Content-Type':  'application/json',
            Prefer:          'return=minimal',
          },
          body: JSON.stringify({ stripe_customer_id: customerId }),
        }
      );
    }

    // ── Create Checkout session ───────────────────────────────────────────────
    const sessionRes = await fetch('https://api.stripe.com/v1/checkout/sessions', {
      method:  'POST',
      headers: {
        Authorization:  `Bearer ${STRIPE_KEY}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        customer:                                    customerId,
        mode:                                        'subscription',
        'line_items[0][price]':                      PRICE_ID,
        'line_items[0][quantity]':                   '1',
        success_url:                                 successUrl,
        cancel_url:                                  cancelUrl,
        // Attach user_id to BOTH session AND subscription for reliable webhook lookup
        'metadata[supabase_user_id]':                userId,
        'subscription_data[metadata][supabase_user_id]': userId,
      }).toString(),
    });

    if (!sessionRes.ok) {
      const err = await sessionRes.text();
      console.error('Stripe session create failed:', err.slice(0, 300));
      return res.status(500).json({ error: 'Could not create checkout session.' });
    }

    const session = await sessionRes.json();
    return res.status(200).json({ url: session.url });

  } catch (err) {
    console.error('create-checkout error:', err.message);
    return res.status(500).json({ error: 'Service temporarily unavailable.' });
  }
}

/**
 * /api/refund — Self-serve refund within 24 hours of purchase
 *
 * POST /api/refund
 *   Verifies the user is authenticated and within the 24-hour refund window,
 *   then issues a Stripe refund and immediately cancels the subscription.
 *   The charge.refunded + customer.subscription.deleted webhooks handle
 *   flipping plan = 'free' in Supabase.
 *
 * Required Vercel env vars:
 *   SUPABASE_URL            — Supabase project URL
 *   SUPABASE_SERVICE_KEY    — service-role key
 *   STRIPE_SECRET_KEY       — Stripe secret key
 */

import Stripe from 'stripe';

const SUPABASE_URL = process.env.SUPABASE_URL || 'https://kknzvaayyihfzkaezhft.supabase.co';
const SERVICE_KEY  = process.env.SUPABASE_SERVICE_KEY;
const STRIPE_KEY   = process.env.STRIPE_SECRET_KEY;

const REFUND_WINDOW_HOURS = 24;

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  if (!SERVICE_KEY || !STRIPE_KEY) {
    return res.status(500).json({ error: 'Service configuration error.' });
  }

  // 1. Authenticate
  const jwt = (req.headers.authorization || '').replace('Bearer ', '').trim();
  if (!jwt) return res.status(401).json({ error: 'Not authenticated.' });

  const authRes = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
    headers: { apikey: SERVICE_KEY, Authorization: `Bearer ${jwt}` },
  });
  if (!authRes.ok) return res.status(401).json({ error: 'Invalid or expired session.' });
  const user = await authRes.json();
  if (!user?.id) return res.status(401).json({ error: 'Could not identify user.' });

  // 2. Get profile
  const profileRes = await fetch(
    `${SUPABASE_URL}/rest/v1/profiles?id=eq.${encodeURIComponent(user.id)}&select=plan,stripe_subscription_id,stripe_customer_id`,
    { headers: { apikey: SERVICE_KEY, Authorization: `Bearer ${SERVICE_KEY}` } }
  );
  const profiles = await profileRes.json();
  const profile  = profiles?.[0];

  if (!profile || profile.plan !== 'pro') {
    return res.status(400).json({ error: 'No active Pro subscription found.' });
  }
  if (!profile.stripe_subscription_id) {
    return res.status(400).json({ error: 'No subscription ID on record.' });
  }

  try {
    const stripe = new Stripe(STRIPE_KEY, { apiVersion: '2023-10-16' });

    // 3. Check the 24-hour window
    const subscription = await stripe.subscriptions.retrieve(
      profile.stripe_subscription_id,
      { expand: ['latest_invoice'] }
    );

    const purchasedAt  = new Date(subscription.created * 1000);
    const hoursSince   = (Date.now() - purchasedAt) / (1000 * 60 * 60);

    if (hoursSince > REFUND_WINDOW_HOURS) {
      return res.status(400).json({
        error: `Refund window has closed. Refunds are only available within ${REFUND_WINDOW_HOURS} hours of purchase.`,
      });
    }

    // 4. Find the charge to refund
    const invoice  = subscription.latest_invoice;
    const chargeId = typeof invoice === 'object' ? invoice.charge : null;

    if (!chargeId) {
      return res.status(400).json({ error: 'No charge found to refund.' });
    }

    // 5. Issue refund + cancel subscription
    await stripe.refunds.create({ charge: chargeId });
    await stripe.subscriptions.cancel(profile.stripe_subscription_id);

    // charge.refunded and customer.subscription.deleted webhooks
    // will flip plan = 'free' in Supabase automatically.
    console.log(`refund: issued refund for user ${user.id}, charge ${chargeId}`);

    return res.status(200).json({ success: true });

  } catch (err) {
    console.error('refund error:', err.message);
    return res.status(500).json({ error: 'Refund failed. Please try again or contact support.' });
  }
}

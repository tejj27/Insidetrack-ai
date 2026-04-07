/**
 * /api/stripe-webhook — Handle Stripe webhook events
 *
 * Uses the official Stripe SDK for reliable raw-body reading and
 * signature verification (replaces the fragile manual implementation).
 *
 * Events handled:
 *   checkout.session.completed      → plan = 'pro', save stripe_subscription_id
 *   customer.subscription.deleted   → plan = 'free', clear stripe_subscription_id
 *   customer.subscription.updated   → downgrade if status goes non-active
 *   invoice.payment_failed          → logged only
 *
 * Required Vercel env vars:
 *   SUPABASE_URL            — Supabase project URL (optional, has fallback)
 *   SUPABASE_SERVICE_KEY    — service-role key
 *   STRIPE_SECRET_KEY       — Stripe secret key
 *   STRIPE_WEBHOOK_SECRET   — whsec_… from Stripe Dashboard > Webhooks
 */

import Stripe from 'stripe';

// Disable Vercel's body parser — Stripe SDK needs the raw bytes
export const config = {
  api: { bodyParser: false },
};

const SUPABASE_URL  = process.env.SUPABASE_URL || 'https://kknzvaayyihfzkaezhft.supabase.co';
const SERVICE_KEY   = process.env.SUPABASE_SERVICE_KEY;
const STRIPE_KEY    = process.env.STRIPE_SECRET_KEY;
const WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;

// ── Supabase helpers ──────────────────────────────────────────────────────────
async function updateProfile(userId, updates) {
  const r = await fetch(
    `${SUPABASE_URL}/rest/v1/profiles?id=eq.${encodeURIComponent(userId)}`,
    {
      method:  'PATCH',
      headers: {
        apikey:         SERVICE_KEY,
        Authorization:  `Bearer ${SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer:         'return=minimal',
      },
      body: JSON.stringify(updates),
    }
  );
  if (!r.ok) {
    const err = await r.text();
    throw new Error(`Profile update failed (${r.status}): ${err.slice(0, 300)}`);
  }
}

async function getUserIdByCustomerId(customerId) {
  const r = await fetch(
    `${SUPABASE_URL}/rest/v1/profiles?stripe_customer_id=eq.${encodeURIComponent(customerId)}&select=id`,
    { headers: { apikey: SERVICE_KEY, Authorization: `Bearer ${SERVICE_KEY}` } }
  );
  if (!r.ok) return null;
  const rows = await r.json();
  return rows?.[0]?.id ?? null;
}

// ── Read raw body as Buffer (required by Stripe SDK) ──────────────────────────
function getRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk));
    req.on('end',  () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

// ── Handler ───────────────────────────────────────────────────────────────────
export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end('Method not allowed');

  if (!SERVICE_KEY || !STRIPE_KEY || !WEBHOOK_SECRET) {
    console.error('stripe-webhook: missing env vars', {
      hasServiceKey: !!SERVICE_KEY,
      hasStripeKey:  !!STRIPE_KEY,
      hasWebhookSecret: !!WEBHOOK_SECRET,
    });
    return res.status(500).end('Configuration error');
  }

  // Read raw bytes for signature verification
  let rawBody;
  try {
    rawBody = await getRawBody(req);
  } catch (err) {
    console.error('stripe-webhook: failed to read body:', err.message);
    return res.status(400).end('Could not read request body');
  }

  // Verify signature using the Stripe SDK
  const stripe = new Stripe(STRIPE_KEY, { apiVersion: '2023-10-16' });
  let event;
  try {
    event = stripe.webhooks.constructEvent(
      rawBody,
      req.headers['stripe-signature'],
      WEBHOOK_SECRET
    );
  } catch (err) {
    console.error('stripe-webhook: signature verification failed:', err.message);
    return res.status(400).end(`Webhook signature error: ${err.message}`);
  }

  console.log(`stripe-webhook: received ${event.type}`);

  try {
    switch (event.type) {

      case 'checkout.session.completed': {
        const session = event.data.object;
        if (session.mode !== 'subscription') break;

        const subscriptionId = session.subscription;
        const customerId     = session.customer;
        const userId =
          session.metadata?.supabase_user_id ||
          (await getUserIdByCustomerId(customerId));

        if (!userId) {
          console.error('checkout.session.completed: no user found for customer', customerId);
          break;
        }

        await updateProfile(userId, {
          plan:                   'pro',
          stripe_customer_id:     customerId,
          stripe_subscription_id: subscriptionId,
        });
        console.log(`stripe-webhook: user ${userId} upgraded to Pro`);
        break;
      }

      case 'customer.subscription.deleted': {
        const sub        = event.data.object;
        const customerId = sub.customer;
        const userId =
          sub.metadata?.supabase_user_id ||
          (await getUserIdByCustomerId(customerId));

        if (!userId) {
          console.error('subscription.deleted: no user found for customer', customerId);
          break;
        }

        await updateProfile(userId, {
          plan:                   'free',
          stripe_subscription_id: null,
        });
        console.log(`stripe-webhook: user ${userId} downgraded to Free`);
        break;
      }

      case 'customer.subscription.updated': {
        const sub = event.data.object;
        if (sub.status === 'active' || sub.status === 'trialing') break;
        if (sub.cancel_at_period_end) break;

        const customerId = sub.customer;
        const userId =
          sub.metadata?.supabase_user_id ||
          (await getUserIdByCustomerId(customerId));

        if (!userId) break;

        await updateProfile(userId, {
          plan:                   'free',
          stripe_subscription_id: null,
        });
        console.log(`stripe-webhook: user ${userId} set to Free (status: ${sub.status})`);
        break;
      }

      case 'invoice.payment_failed':
        console.log(`stripe-webhook: payment failed for customer ${event.data.object.customer}`);
        break;

      default:
        console.log(`stripe-webhook: ignoring ${event.type}`);
    }
  } catch (err) {
    console.error(`stripe-webhook: error handling ${event.type}:`, err.message);
    return res.status(500).end('Webhook handler error');
  }

  return res.status(200).json({ received: true });
}

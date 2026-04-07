/**
 * /api/stripe-webhook — Handle Stripe webhook events
 *
 * Events handled:
 *   checkout.session.completed      → plan = 'pro', save stripe_subscription_id
 *   customer.subscription.deleted   → plan = 'free', clear stripe_subscription_id
 *   customer.subscription.updated   → downgrade if status goes non-active
 *   invoice.payment_failed          → logged only (Stripe retries before deleting)
 *
 * IMPORTANT: body parsing must be disabled so we can verify the raw signature.
 *
 * Required Vercel env vars:
 *   SUPABASE_URL            — Supabase project URL
 *   SUPABASE_SERVICE_KEY    — service-role key
 *   STRIPE_WEBHOOK_SECRET   — whsec_… from Stripe Dashboard > Webhooks
 */

import crypto from 'crypto';

// Tell Vercel NOT to parse the body — we need the raw bytes for signature verification
export const config = {
  api: { bodyParser: false },
};

const SUPABASE_URL  = process.env.SUPABASE_URL || 'https://kknzvaayyihfzkaezhft.supabase.co';
const SERVICE_KEY   = process.env.SUPABASE_SERVICE_KEY;
const WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;

// ── Stripe signature verification ─────────────────────────────────────────────
function verifyStripeSignature(rawBody, sigHeader, secret) {
  // Parse "t=...,v1=..." header
  const parts = Object.fromEntries(
    sigHeader.split(',').map(p => p.split('=')).filter(p => p.length === 2)
  );
  const { t: timestamp, v1: sig } = parts;
  if (!timestamp || !sig) return false;

  // Reject if event is older than 5 minutes (replay-attack protection)
  if (Math.abs(Date.now() - Number(timestamp) * 1000) > 5 * 60 * 1000) return false;

  const expected = crypto
    .createHmac('sha256', secret)
    .update(`${timestamp}.${rawBody}`, 'utf8')
    .digest('hex');

  try {
    return crypto.timingSafeEqual(
      Buffer.from(expected, 'hex'),
      Buffer.from(sig,      'hex')
    );
  } catch {
    return false;
  }
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => (body += chunk.toString()));
    req.on('end',  () => resolve(body));
    req.on('error', reject);
  });
}

// ── Supabase helpers (service-role — server only) ─────────────────────────────
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
    throw new Error(`Profile update failed (${r.status}): ${err.slice(0, 200)}`);
  }
}

// Fallback lookup when metadata doesn't carry user_id (e.g. old subscriptions)
async function getUserIdByCustomerId(customerId) {
  const r = await fetch(
    `${SUPABASE_URL}/rest/v1/profiles?stripe_customer_id=eq.${encodeURIComponent(customerId)}&select=id`,
    { headers: { apikey: SERVICE_KEY, Authorization: `Bearer ${SERVICE_KEY}` } }
  );
  if (!r.ok) return null;
  const rows = await r.json();
  return rows?.[0]?.id ?? null;
}

// ── Handler ───────────────────────────────────────────────────────────────────
export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end('Method not allowed');

  if (!SUPABASE_URL || !SERVICE_KEY || !WEBHOOK_SECRET) {
    console.error('stripe-webhook: missing env vars');
    return res.status(500).end('Configuration error');
  }

  // Read raw body BEFORE any parsing
  const rawBody   = await readRawBody(req);
  const sigHeader = req.headers['stripe-signature'] || '';

  if (!verifyStripeSignature(rawBody, sigHeader, WEBHOOK_SECRET)) {
    console.error('stripe-webhook: signature verification failed');
    return res.status(400).end('Invalid signature');
  }

  let event;
  try {
    event = JSON.parse(rawBody);
  } catch {
    return res.status(400).end('Invalid JSON');
  }

  console.log(`stripe-webhook: received ${event.type}`);

  try {
    switch (event.type) {

      // ── Payment succeeded → activate Pro ───────────────────────────────────
      case 'checkout.session.completed': {
        const session = event.data.object;
        if (session.mode !== 'subscription') break;

        const subscriptionId = session.subscription;
        const customerId     = session.customer;

        // Prefer metadata on the session (set in create-checkout); fall back to DB lookup
        const userId =
          session.metadata?.supabase_user_id ||
          (await getUserIdByCustomerId(customerId));

        if (!userId) {
          console.error('checkout.session.completed: cannot resolve user for customer', customerId);
          break;
        }

        await updateProfile(userId, {
          plan:                   'pro',
          stripe_subscription_id: subscriptionId,
        });
        console.log(`stripe-webhook: user ${userId} upgraded to Pro`);
        break;
      }

      // ── Subscription cancelled → revert to Free ─────────────────────────────
      case 'customer.subscription.deleted': {
        const sub        = event.data.object;
        const customerId = sub.customer;

        const userId =
          sub.metadata?.supabase_user_id ||
          (await getUserIdByCustomerId(customerId));

        if (!userId) {
          console.error('subscription.deleted: cannot resolve user for customer', customerId);
          break;
        }

        await updateProfile(userId, {
          plan:                   'free',
          stripe_subscription_id: null,
        });
        console.log(`stripe-webhook: user ${userId} downgraded to Free`);
        break;
      }

      // ── Subscription status changed (paused, past_due, etc.) ─────────────────
      case 'customer.subscription.updated': {
        const sub = event.data.object;

        // Still active (or scheduled to cancel at period end) — leave as Pro
        if (sub.status === 'active' || sub.status === 'trialing') break;
        if (sub.cancel_at_period_end) break; // access until period ends

        // Non-recoverable states: canceled, unpaid → downgrade now
        const customerId = sub.customer;
        const userId =
          sub.metadata?.supabase_user_id ||
          (await getUserIdByCustomerId(customerId));

        if (!userId) break;

        await updateProfile(userId, {
          plan:                   'free',
          stripe_subscription_id: null,
        });
        console.log(`stripe-webhook: user ${userId} set to Free (subscription status: ${sub.status})`);
        break;
      }

      // ── Payment failed — log only, Stripe retries automatically ───────────────
      case 'invoice.payment_failed': {
        const invoice = event.data.object;
        console.log(`stripe-webhook: payment failed for customer ${invoice.customer}, attempt ${invoice.attempt_count}`);
        break;
      }

      default:
        // Acknowledge all other events without error
        console.log(`stripe-webhook: ignoring event type ${event.type}`);
    }
  } catch (err) {
    console.error(`stripe-webhook: error handling ${event.type}:`, err.message);
    // Return 500 so Stripe retries the webhook
    return res.status(500).end('Webhook handler error');
  }

  return res.status(200).json({ received: true });
}

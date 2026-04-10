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

async function getProfile(userId) {
  const r = await fetch(
    `${SUPABASE_URL}/rest/v1/profiles?id=eq.${encodeURIComponent(userId)}&select=email,full_name`,
    { headers: { apikey: SERVICE_KEY, Authorization: `Bearer ${SERVICE_KEY}` } }
  );
  if (!r.ok) return null;
  const rows = await r.json();
  return rows?.[0] ?? null;
}

async function sendProEmail(email, name) {
  const RESEND_KEY = process.env.RESEND_API_KEY;
  if (!RESEND_KEY || !email) return;
  const safeName = name ? name.split(' ')[0] : '';
  try {
    await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Content-Type':  'application/json',
        'Authorization': `Bearer ${RESEND_KEY}`,
      },
      body: JSON.stringify({
        from:    'InsideTrack <hello@insidetrack.site>',
        to:      [email],
        subject: "You're now on InsideTrack Pro ⭐",
        html: `
          <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;padding:40px 20px">
            <div style="text-align:center;margin-bottom:32px">
              <h1 style="font-size:28px;color:#1a1814;margin:0">InsideTrack<span style="color:#7c3aed">.site</span></h1>
              <p style="color:#6a6560;font-size:14px;margin-top:4px">AI Career Copilot</p>
            </div>
            <h2 style="color:#1a1814;font-size:22px">You're on Pro${safeName ? ', ' + safeName : ''}! ⭐</h2>
            <p style="color:#4a4640;font-size:15px;line-height:1.7">
              Your InsideTrack Pro subscription is now active. You have <strong>unlimited CV scans</strong> and full access to all tools.
            </p>
            <div style="background:#f5f0eb;border-radius:12px;padding:24px;margin:24px 0">
              <p style="font-weight:700;color:#1a1814;margin:0 0 12px">Your Pro plan includes:</p>
              <p style="color:#4a4640;margin:6px 0">⚡ Unlimited ATS scans</p>
              <p style="color:#4a4640;margin:6px 0">✅ CV Builder</p>
              <p style="color:#4a4640;margin:6px 0">✅ CV Tailor</p>
              <p style="color:#4a4640;margin:6px 0">✅ Cover Letter AI</p>
              <p style="color:#4a4640;margin:6px 0">✅ Outreach AI</p>
              <p style="color:#4a4640;margin:6px 0">✅ Application Tracker</p>
            </div>
            <div style="text-align:center;margin:32px 0">
              <a href="https://insidetrack.site" style="background:#7c3aed;color:white;padding:14px 32px;border-radius:10px;text-decoration:none;font-weight:700;font-size:15px;display:inline-block">
                Start using InsideTrack Pro →
              </a>
            </div>
            <p style="color:#9a9590;font-size:12px;text-align:center;margin-top:32px">
              You can manage or cancel your subscription anytime from your account menu.<br><br>
              Good luck with your applications 🚀<br>
              The InsideTrack team
            </p>
          </div>
        `,
      }),
    });
    console.log(`stripe-webhook: pro email sent to ${email}`);
  } catch (err) {
    console.error('stripe-webhook: failed to send pro email:', err.message);
  }
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

        // Send Pro upgrade confirmation email
        const profile = await getProfile(userId);
        if (profile?.email) {
          await sendProEmail(profile.email, profile.full_name);
        }
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
          cancel_at_period_end:   false,
          current_period_end:     null,
        });
        console.log(`stripe-webhook: user ${userId} downgraded to Free`);
        break;
      }

      case 'customer.subscription.updated': {
        const sub        = event.data.object;
        const customerId = sub.customer;
        const userId =
          sub.metadata?.supabase_user_id ||
          (await getUserIdByCustomerId(customerId));

        if (!userId) break;

        if (sub.cancel_at_period_end) {
          // Scheduled cancellation — keep Pro but record the end date
          await updateProfile(userId, {
            cancel_at_period_end: true,
            current_period_end:   new Date(sub.current_period_end * 1000).toISOString(),
          });
          console.log(`stripe-webhook: user ${userId} scheduled to cancel at period end`);
          break;
        }

        if (sub.status === 'active' || sub.status === 'trialing') {
          // Reactivated (un-cancelled) — clear the scheduled cancellation
          await updateProfile(userId, {
            cancel_at_period_end: false,
            current_period_end:   null,
          });
          console.log(`stripe-webhook: user ${userId} reactivated`);
          break;
        }

        // Status went bad (past_due, unpaid, etc.) — downgrade
        await updateProfile(userId, {
          plan:                   'free',
          stripe_subscription_id: null,
          cancel_at_period_end:   false,
          current_period_end:     null,
        });
        console.log(`stripe-webhook: user ${userId} set to Free (status: ${sub.status})`);
        break;
      }

      case 'charge.refunded': {
        // Refund issued — remove access immediately regardless of billing period
        const charge     = event.data.object;
        const customerId = charge.customer;
        if (!customerId) break;

        const userId = await getUserIdByCustomerId(customerId);
        if (!userId) break;

        await updateProfile(userId, {
          plan:                   'free',
          stripe_subscription_id: null,
          cancel_at_period_end:   false,
          current_period_end:     null,
        });
        console.log(`stripe-webhook: user ${userId} refunded → downgraded to Free immediately`);
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

/**
 * /api/send-email — Welcome email proxy with security hardening
 *
 * Security layers:
 *  1. CORS — only allow known origins
 *  2. Rate limiting — 5 emails / hour per IP (prevents spam/abuse)
 *  3. Input validation — email format check, length limits
 *  4. HTML sanitisation — strip tags from name before use in email body
 *  5. Sanitised errors — never leak internal details to the client
 */

const ALLOWED_ORIGINS = [
  'https://insidetrack-ai.vercel.app',
  'https://insidetrack.ai',
  'http://localhost:3000',
  'http://localhost:5173',
  'http://127.0.0.1:5500',
];

const RATE_LIMIT_MAX    = 5;
const RATE_LIMIT_WINDOW = 60 * 60 * 1000; // 1 hour
const MAX_NAME_LENGTH   = 100;
const MAX_EMAIL_LENGTH  = 254; // RFC 5321

const emailRateLimitStore = new Map();

function getClientIP(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return forwarded.split(',')[0].trim();
  return req.socket?.remoteAddress || 'unknown';
}

function checkRateLimit(ip) {
  const now = Date.now();
  let entry = emailRateLimitStore.get(ip);
  if (!entry || now > entry.resetAt) {
    entry = { count: 0, resetAt: now + RATE_LIMIT_WINDOW };
  }
  entry.count += 1;
  emailRateLimitStore.set(ip, entry);
  return {
    allowed:    entry.count <= RATE_LIMIT_MAX,
    retryAfter: Math.ceil((entry.resetAt - now) / 60), // minutes
  };
}

// Strip all HTML tags and dangerous characters from user-supplied name
function sanitiseName(name) {
  if (!name) return '';
  return String(name)
    .replace(/<[^>]*>/g, '')          // strip HTML tags
    .replace(/[<>&"'`]/g, '')         // strip remaining special chars
    .replace(/[\x00-\x1F\x7F]/g, '')  // strip control characters
    .slice(0, MAX_NAME_LENGTH)
    .trim();
}

function isValidEmail(email) {
  if (!email || typeof email !== 'string') return false;
  if (email.length > MAX_EMAIL_LENGTH) return false;
  // Basic RFC-compliant check (not exhaustive, good enough for this use case)
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

export default async function handler(req, res) {

  // 1. CORS
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

  // 2. Rate limiting (per IP, 1-hour window)
  const ip = getClientIP(req);
  const rate = checkRateLimit(ip);
  if (!rate.allowed) {
    res.setHeader('Retry-After', rate.retryAfter * 60);
    return res.status(429).json({ error: `Too many requests. Please try again in ${rate.retryAfter} minutes.` });
  }

  // 3. Input validation
  const body = req.body;
  if (!body || typeof body !== 'object') {
    return res.status(400).json({ error: 'Invalid request body.' });
  }

  const { to, name } = body;

  if (!to || !isValidEmail(to)) {
    return res.status(400).json({ error: 'A valid email address is required.' });
  }

  // 4. Sanitise name before embedding in email HTML
  const safeName = sanitiseName(name);

  try {
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.RESEND_API_KEY}`,
      },
      body: JSON.stringify({
        from: 'InsideTrack.ai <onboarding@resend.dev>',
        to: ['tejal3488@gmail.com'], // internal notification — to field intentionally fixed
        subject: 'New InsideTrack.ai sign-up 🎉',
        html: `
          <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;padding:40px 20px">
            <div style="text-align:center;margin-bottom:32px">
              <h1 style="font-size:28px;color:#1a1814;margin:0">InsideTrack<span style="color:#7c3aed">.ai</span></h1>
              <p style="color:#6a6560;font-size:14px;margin-top:4px">AI Career Copilot</p>
            </div>

            <h2 style="color:#1a1814;font-size:22px">Welcome${safeName ? ', ' + safeName : ''}! 👋</h2>
            <p style="color:#4a4640;font-size:15px;line-height:1.7">
              Thanks for signing up to InsideTrack.ai. You now have access to all our AI tools.
            </p>

            <div style="background:#f5f0eb;border-radius:12px;padding:24px;margin:24px 0">
              <p style="font-weight:700;color:#1a1814;margin:0 0 12px">Your free account includes:</p>
              <p style="color:#4a4640;margin:6px 0">✅ 3 ATS scans</p>
              <p style="color:#4a4640;margin:6px 0">✅ CV Tailor</p>
              <p style="color:#4a4640;margin:6px 0">✅ Cover Letter AI</p>
              <p style="color:#4a4640;margin:6px 0">✅ Outreach AI</p>
              <p style="color:#4a4640;margin:6px 0">✅ CV Builder</p>
              <p style="color:#4a4640;margin:6px 0">✅ Application Tracker</p>
            </div>

            <div style="text-align:center;margin:32px 0">
              <a href="https://insidetrack-ai.vercel.app" style="background:#7c3aed;color:white;padding:14px 32px;border-radius:10px;text-decoration:none;font-weight:700;font-size:15px;display:inline-block">
                Start using InsideTrack →
              </a>
            </div>

            <p style="color:#9a9590;font-size:12px;text-align:center;margin-top:32px">
              Good luck with your applications 🚀<br>
              The InsideTrack team
            </p>
          </div>
        `,
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      console.error('Resend error:', response.status, JSON.stringify(data).slice(0, 200));
      return res.status(500).json({ error: 'Could not send email. Please try again.' });
    }

    return res.status(200).json({ success: true });

  } catch (err) {
    console.error('send-email error:', err.message);
    return res.status(500).json({ error: 'Service temporarily unavailable.' });
  }
}

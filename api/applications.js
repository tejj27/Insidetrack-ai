/**
 * /api/applications — Job application tracker (Supabase-backed)
 *
 * GET    — fetch all applications for the authenticated user
 * POST   — create a new application
 * PATCH  — update status (or any field) on an existing application
 * DELETE — remove an application
 *
 * All actions require a valid JWT in the Authorization header.
 */

const SUPA_URL         = process.env.SUPABASE_URL || 'https://kknzvaayyihfzkaezhft.supabase.co';
const SUPA_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;

const ALLOWED_ORIGINS = [
  'https://insidetrack-ai.vercel.app',
  'https://insidetrack.site',
  'https://insidetrack.ai',
  'http://localhost:3000',
  'http://localhost:5173',
  'http://127.0.0.1:5500',
];

const ALLOWED_STATUSES = ['applied', 'interview', 'offer', 'rejected'];
const ALLOWED_SOURCES  = ['LinkedIn', 'Indeed', 'Referral', 'Company site', 'Other'];

// ── Auth helper ───────────────────────────────────────────────────────────────
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

// ── Supabase REST helpers (service-role key) ──────────────────────────────────
const SVC_HEADERS = () => ({
  'apikey':        SUPA_SERVICE_KEY,
  'Authorization': 'Bearer ' + SUPA_SERVICE_KEY,
  'Content-Type':  'application/json',
  'Prefer':        'return=representation',
});

// ── Handler ───────────────────────────────────────────────────────────────────
export default async function handler(req, res) {

  // CORS
  const origin = req.headers.origin || '';
  if (ALLOWED_ORIGINS.includes(origin)) res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Vary', 'Origin');
  res.setHeader('Cache-Control', 'no-store');

  if (req.method === 'OPTIONS') return res.status(200).end();

  if (!['GET','POST','PATCH','DELETE'].includes(req.method)) {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // Service key check
  if (!SUPA_SERVICE_KEY) {
    console.error('SUPABASE_SERVICE_KEY not set');
    return res.status(500).json({ error: 'Service configuration error.' });
  }

  // Auth — all operations require a valid JWT
  const authHeader = req.headers.authorization || '';
  const jwt = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : null;
  if (!jwt) return res.status(401).json({ error: 'Authentication required.' });

  const user = await validateJWT(jwt);
  if (!user) return res.status(401).json({ error: 'Invalid or expired session. Please sign in again.' });

  const userId = user.id;

  // ── GET: fetch all applications for this user ─────────────────────────────
  if (req.method === 'GET') {
    try {
      const r = await fetch(
        `${SUPA_URL}/rest/v1/applications?user_id=eq.${userId}&order=created_at.desc`,
        { headers: SVC_HEADERS() }
      );
      if (!r.ok) throw new Error(await r.text());
      const data = await r.json();
      return res.status(200).json(data);
    } catch (err) {
      console.error('applications GET error:', err.message);
      return res.status(500).json({ error: 'Could not fetch applications.' });
    }
  }

  // ── POST: create a new application ───────────────────────────────────────
  if (req.method === 'POST') {
    const { company, role, ats_score, source, status } = req.body || {};

    if (!company || typeof company !== 'string' || !company.trim()) {
      return res.status(400).json({ error: 'company is required.' });
    }
    if (!role || typeof role !== 'string' || !role.trim()) {
      return res.status(400).json({ error: 'role is required.' });
    }
    if (status && !ALLOWED_STATUSES.includes(status)) {
      return res.status(400).json({ error: 'Invalid status.' });
    }

    const record = {
      user_id:   userId,
      company:   company.trim().slice(0, 200),
      role:      role.trim().slice(0, 200),
      status:    ALLOWED_STATUSES.includes(status) ? status : 'applied',
      source:    (typeof source === 'string' && source.trim()) ? source.trim().slice(0, 100) : 'Other',
      ats_score: (typeof ats_score === 'number' && ats_score >= 0 && ats_score <= 100) ? Math.round(ats_score) : null,
    };

    try {
      const r = await fetch(`${SUPA_URL}/rest/v1/applications`, {
        method:  'POST',
        headers: SVC_HEADERS(),
        body:    JSON.stringify(record),
      });
      if (!r.ok) throw new Error(await r.text());
      const [created] = await r.json();
      return res.status(201).json(created);
    } catch (err) {
      console.error('applications POST error:', err.message);
      return res.status(500).json({ error: 'Could not save application.' });
    }
  }

  // ── PATCH: update fields on an existing application ───────────────────────
  if (req.method === 'PATCH') {
    const { id, status, company, role, ats_score, source } = req.body || {};

    if (!id || typeof id !== 'string') {
      return res.status(400).json({ error: 'id is required.' });
    }

    // Build update — only allow known fields
    const update = {};
    if (status !== undefined) {
      if (!ALLOWED_STATUSES.includes(status)) return res.status(400).json({ error: 'Invalid status.' });
      update.status = status;
    }
    if (company !== undefined) update.company = String(company).trim().slice(0, 200);
    if (role    !== undefined) update.role    = String(role).trim().slice(0, 200);
    if (source  !== undefined) update.source  = String(source).trim().slice(0, 100);
    if (ats_score !== undefined) {
      update.ats_score = (typeof ats_score === 'number' && ats_score >= 0 && ats_score <= 100)
        ? Math.round(ats_score) : null;
    }

    if (!Object.keys(update).length) {
      return res.status(400).json({ error: 'No valid fields to update.' });
    }

    try {
      // user_id filter ensures users can only update their own rows
      const r = await fetch(
        `${SUPA_URL}/rest/v1/applications?id=eq.${encodeURIComponent(id)}&user_id=eq.${userId}`,
        { method: 'PATCH', headers: SVC_HEADERS(), body: JSON.stringify(update) }
      );
      if (!r.ok) throw new Error(await r.text());
      const [updated] = await r.json();
      if (!updated) return res.status(404).json({ error: 'Application not found.' });
      return res.status(200).json(updated);
    } catch (err) {
      console.error('applications PATCH error:', err.message);
      return res.status(500).json({ error: 'Could not update application.' });
    }
  }

  // ── DELETE: remove an application ─────────────────────────────────────────
  if (req.method === 'DELETE') {
    const { id } = req.body || {};
    if (!id || typeof id !== 'string') {
      return res.status(400).json({ error: 'id is required.' });
    }

    try {
      const r = await fetch(
        `${SUPA_URL}/rest/v1/applications?id=eq.${encodeURIComponent(id)}&user_id=eq.${userId}`,
        { method: 'DELETE', headers: { ...SVC_HEADERS(), 'Prefer': 'return=minimal' } }
      );
      if (!r.ok) throw new Error(await r.text());
      return res.status(200).json({ success: true });
    } catch (err) {
      console.error('applications DELETE error:', err.message);
      return res.status(500).json({ error: 'Could not delete application.' });
    }
  }
}

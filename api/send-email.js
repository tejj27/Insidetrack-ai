export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { to, name } = req.body;
  if (!to) return res.status(400).json({ error: 'Email required' });

  try {
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.RESEND_API_KEY}`
      },
      body: JSON.stringify({
        from: 'onboarding@resend.dev',
        to: [to],
        subject: 'Welcome to InsideTrack.ai 🎉',
        html: `
          <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;padding:40px 20px">
            <div style="text-align:center;margin-bottom:32px">
              <h1 style="font-size:28px;color:#1a1814;margin:0">InsideTrack<span style="color:#1a6b3c">.ai</span></h1>
              <p style="color:#6a6560;font-size:14px;margin-top:4px">AI Job Search Copilot</p>
            </div>

            <h2 style="color:#1a1814;font-size:22px">Welcome${name ? ', ' + name : ''}! 👋</h2>
            <p style="color:#4a4640;font-size:15px;line-height:1.7">
              Thanks for signing up to InsideTrack.ai. You now have access to all our AI-powered job search tools.
            </p>

            <div style="background:#f5f0eb;border-radius:12px;padding:24px;margin:24px 0">
              <p style="font-weight:700;color:#1a1814;margin:0 0 12px">Your free account includes:</p>
              <p style="color:#4a4640;margin:6px 0">✅ 3 ATS scans</p>
              <p style="color:#4a4640;margin:6px 0">✅ 1 CV tailor</p>
              <p style="color:#4a4640;margin:6px 0">✅ Outreach AI — LinkedIn messages</p>
              <p style="color:#4a4640;margin:6px 0">✅ Visa Sponsor Finder</p>
              <p style="color:#4a4640;margin:6px 0">✅ Cover Letter AI</p>
              <p style="color:#4a4640;margin:6px 0">✅ Application Tracker</p>
            </div>

            <div style="text-align:center;margin:32px 0">
              <a href="https://insidetrack-ai.vercel.app" style="background:#1a6b3c;color:white;padding:14px 32px;border-radius:10px;text-decoration:none;font-weight:700;font-size:15px;display:inline-block">
                Start using InsideTrack →
              </a>
            </div>

            <div style="background:#fff8e6;border:1px solid #f0c040;border-radius:10px;padding:16px;margin:24px 0">
              <p style="color:#7a4500;font-size:13px;margin:0">
                <strong>Want unlimited scans?</strong> Upgrade to Pro for just £7/month — unlimited CV scans, tailoring and priority AI.
              </p>
            </div>

            <p style="color:#9a9590;font-size:12px;text-align:center;margin-top:32px">
              Good luck with your applications 🚀<br>
              The InsideTrack team
            </p>
          </div>
        `
      })
    });

    const data = await response.json();
    if (!response.ok) throw new Error(data.message || 'Failed to send email');
    return res.status(200).json({ success: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
}

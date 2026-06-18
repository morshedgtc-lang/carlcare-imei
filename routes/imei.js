const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const db = require('../utils/db');
const { SignatureGenerator, extractDeviceDetails, encryptRcsmImei, buildRcsmUrl, parseRcsmResponse, loadRcsmToken, saveRcsmToken, clearRcsmToken, isRcsmTokenValid, RCSM_BASE } = require('../utils/signature');
const { JWT_SECRET } = require('./auth');
const { isIpBlocked, recordFailedAttempt, requireHmac } = require('../utils/verify');

const router = express.Router();
const signatureGen = new SignatureGenerator();

const requireAuth = (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'No token' });
  try {
    const decoded = jwt.verify(auth.replace('Bearer ', ''), JWT_SECRET);
    if (decoded.role !== 'client' && decoded.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }
    if (isIpBlocked(req.ip)) return res.status(403).json({ error: 'IP blocked due to suspicious activity' });
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
};

router.post('/login', async (req, res) => {
  try {
    const sign = signatureGen.generateLoginSign();
    const url = `${signatureGen.apiBaseUrl}/CarlcareClient/select-aicc-login?mcc=000`;
    const response = await axios.get(url, {
      headers: {
        'accept': 'application/json, text/plain, */*',
        'sign': sign,
        'origin': 'https://www.carlcare.com',
        'referer': 'https://www.carlcare.com/'
      },
      timeout: 10000
    });
    if (response.data.code !== 200) {
      return res.json({ success: false, error: response.data.message || 'Login failed.' });
    }
    res.json({ success: true, data: response.data });
  } catch (error) {
    console.error('Login error:', error.message);
    res.json({
      success: false,
      error: error.response?.data?.message || error.message || 'Login request failed.'
    });
  }
});

router.post('/check-imei', requireAuth, requireHmac, async (req, res) => {
  try {
    const { imei } = req.body;
    if (!imei || !/^\d{15}$/.test(imei)) {
      return res.status(400).json({ success: false, error: 'Invalid IMEI. Must be 15 digits.' });
    }

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
    if (!user || user.status !== 'active') {
      return res.status(403).json({ success: false, error: 'Account not active' });
    }

    const costSetting = db.prepare("SELECT value FROM settings WHERE key = 'per_check_cost'").get();
    const perCheckCost = costSetting ? parseInt(costSetting.value) || 1 : 1;
    if (user.credits < perCheckCost && user.role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Insufficient credits' });
    }

    const url = signatureGen.buildImeiInfoUrl(imei);
    const headers = {
      'accept': 'application/json, text/plain, */*',
      'accept-language': 'en-US,en;q=0.9',
      'origin': 'https://www.carlcare.com',
      'referer': 'https://www.carlcare.com/',
      'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    };

    const response = await axios.get(url, { headers, timeout: 10000 });

    if (user.role !== 'admin') {
      db.prepare('UPDATE users SET credits = credits - ? WHERE id = ?').run(perCheckCost, req.user.id);
      db.prepare('INSERT INTO credit_logs (user_id, amount, type, note) VALUES (?, ?, ?, ?)')
        .run(req.user.id, -perCheckCost, 'deduct', `IMEI check: ${imei}`);
    }

    db.prepare('INSERT INTO imei_logs (user_id, imei, response_status, ip) VALUES (?, ?, ?, ?)')
      .run(req.user.id, imei, response.data.code || 0, req.ip);

    if (response.data.code !== 200) {
      return res.status(400).json({
        success: false,
        error: response.data.message || 'IMEI lookup failed.'
      });
    }

    const deviceDetails = extractDeviceDetails(response.data);
    if (!deviceDetails) {
      return res.status(404).json({ success: false, error: 'Device information not found.' });
    }

    const remaining = user.role === 'admin' ? user.credits : db.prepare('SELECT credits FROM users WHERE id = ?').get(req.user.id).credits;
    res.json({ success: true, data: deviceDetails, credits_remaining: remaining });

  } catch (error) {
    console.error('IMEI lookup error:', error.message);
    if (error.response) {
      return res.status(error.response.status).json({
        success: false, error: `API Error: ${error.response.data?.message || error.message}`
      });
    }
    if (error.code === 'ECONNABORTED') {
      return res.status(504).json({ success: false, error: 'Request timeout. Please try again.' });
    }
    res.status(500).json({ success: false, error: 'Internal server error.' });
  }
});

router.get('/history', requireAuth, requireHmac, (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 20;
  const offset = (page - 1) * limit;
  const logs = db.prepare('SELECT * FROM imei_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?')
    .all(req.user.id, limit, offset);
  const total = db.prepare('SELECT COUNT(*) as count FROM imei_logs WHERE user_id = ?').get(req.user.id).count;
  res.json({ logs, total, page, limit });
});

router.get('/credit-logs', requireAuth, requireHmac, (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 20;
  const offset = (page - 1) * limit;
  const logs = db.prepare('SELECT * FROM credit_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?')
    .all(req.user.id, limit, offset);
  const total = db.prepare('SELECT COUNT(*) as count FROM credit_logs WHERE user_id = ?').get(req.user.id).count;
  res.json({ logs, total, page, limit });
});

router.get('/keys', requireAuth, requireHmac, (req, res) => {
  const keys = db.prepare('SELECT * FROM api_keys WHERE user_id = ? ORDER BY created_at DESC').all(req.user.id);
  res.json({ keys });
});

router.post('/keys', requireAuth, requireHmac, (req, res) => {
  const { label } = req.body;
  const raw = crypto.randomBytes(24).toString('hex');
  const key = 'sk_live_' + raw;
  const hash = crypto.createHash('sha256').update(key).digest('hex');
  db.prepare('INSERT INTO api_keys (user_id, key, label) VALUES (?, ?, ?)').run(req.user.id, hash, label || 'Default');
  res.json({ message: 'Key generated', key });
});

router.delete('/keys/:id', requireAuth, requireHmac, (req, res) => {
  const keyRec = db.prepare('SELECT * FROM api_keys WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!keyRec) return res.status(404).json({ error: 'Key not found' });
  db.prepare('UPDATE api_keys SET active = 0 WHERE id = ?').run(req.params.id);
  res.json({ message: 'Key revoked' });
});

let latestToken = null;

router.get('/token-ping/:token', (req, res) => {
  latestToken = req.params.token;
  res.set('Access-Control-Allow-Origin', '*');
  res.type('gif');
  res.send(Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64'));
});

router.get('/token-latest', (req, res) => {
  res.json({ success: !!latestToken, token: latestToken || null });
});

router.post('/check-rcsm', requireAuth, requireHmac, async (req, res) => {
  try {
    const { imei } = req.body;
    if (!imei || !/^\d{15}$/.test(imei)) {
      return res.status(400).json({ success: false, error: 'Invalid IMEI. Must be 15 digits.' });
    }

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
    if (!user || user.status !== 'active') {
      return res.status(403).json({ success: false, error: 'Account not active' });
    }

    const costSetting = db.prepare("SELECT value FROM settings WHERE key = 'per_check_cost'").get();
    const perCheckCost = costSetting ? parseInt(costSetting.value) || 1 : 1;
    if (user.credits < perCheckCost && user.role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Insufficient credits' });
    }

    const tokenData = loadRcsmToken();
    if (!tokenData || !tokenData.accessToken) {
      return res.status(503).json({ success: false, error: 'RCSM token not configured. Admin must add a token first.' });
    }
    if (!isRcsmTokenValid()) {
      return res.status(503).json({ success: false, error: 'RCSM token expired. Admin must refresh it.' });
    }

    const encrypted = encryptRcsmImei(imei);
    const url = buildRcsmUrl(encrypted);
    const response = await axios.get(url, {
      headers: {
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US',
        'Authorization': 'Bearer ' + tokenData.accessToken,
        'Connection': 'keep-alive',
        'Referer': RCSM_BASE + '/',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin'
      },
      timeout: 15000
    });

    if (user.role !== 'admin') {
      db.prepare('UPDATE users SET credits = credits - ? WHERE id = ?').run(perCheckCost, req.user.id);
      db.prepare('INSERT INTO credit_logs (user_id, amount, type, note) VALUES (?, ?, ?, ?)')
        .run(req.user.id, -perCheckCost, 'deduct', `RCSM IMEI check: ${imei}`);
    }

    db.prepare('INSERT INTO imei_logs (user_id, imei, response_status, ip) VALUES (?, ?, ?, ?)')
      .run(req.user.id, imei, response.data.ErrorCode === 0 ? 200 : 0, req.ip);

    const deviceDetails = parseRcsmResponse(response.data);
    if (!deviceDetails) {
      return res.status(404).json({ success: false, error: 'Device information not found.' });
    }

    const remaining = user.role === 'admin' ? user.credits : db.prepare('SELECT credits FROM users WHERE id = ?').get(req.user.id).credits;
    res.json({ success: true, data: deviceDetails, credits_remaining: remaining });

  } catch (error) {
    console.error('RCSM IMEI lookup error:', error.message);
    if (error.response) {
      return res.status(error.response.status).json({
        success: false, error: `RCSM API Error: ${error.response.data?.Message || error.message}`
      });
    }
    if (error.code === 'ECONNABORTED') {
      return res.status(504).json({ success: false, error: 'RCSM request timeout. Please try again.' });
    }
    res.status(500).json({ success: false, error: 'Internal server error.' });
  }
});

router.get('/rcsm-token-status', requireAuth, requireHmac, (req, res) => {
  const t = loadRcsmToken();
  if (!t || !t.accessToken) {
    return res.json({ valid: false, message: 'No RCSM token saved' });
  }
  const valid = isRcsmTokenValid();
  const msLeft = (t.expiresAt || 0) - Date.now();
  res.json({
    valid,
    expiresAt: new Date(t.expiresAt).toISOString(),
    minutesLeft: Math.max(0, Math.round(msLeft / 60000)),
    savedAt: t.savedAt
  });
});

router.post('/rcsm-token', requireAuth, requireHmac, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin only' });
  }
  const { accessToken, refreshToken, expiresIn } = req.body;
  if (!accessToken) return res.status(400).json({ error: 'accessToken required' });
  const tokenData = {
    accessToken,
    refreshToken: refreshToken || null,
    expiresAt: Date.now() + (expiresIn || 7200) * 1000,
    savedAt: new Date().toISOString()
  };
  saveRcsmToken(tokenData);
  res.json({ ok: true, expiresAt: new Date(tokenData.expiresAt).toISOString() });
});

router.post('/rcsm-token-capture', (req, res) => {
  const { accessToken, refreshToken, expiresIn } = req.body;
  if (!accessToken) return res.status(400).json({ ok: false, error: 'accessToken required' });
  const tokenData = {
    accessToken,
    refreshToken: refreshToken || null,
    expiresAt: Date.now() + (expiresIn || 7200) * 1000,
    savedAt: new Date().toISOString()
  };
  saveRcsmToken(tokenData);
  res.json({ ok: true, expiresAt: new Date(tokenData.expiresAt).toISOString() });
});

router.post('/rcsm-token-refresh', requireAuth, requireHmac, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin only' });
  }
  const t = loadRcsmToken();
  if (!t || !t.refreshToken) {
    return res.status(400).json({ error: 'No refresh token available' });
  }
  try {
    const response = await axios.post(RCSM_BASE + '/token',
      `grant_type=refresh_token&refresh_token=${encodeURIComponent(t.refreshToken)}`,
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 10000 }
    );
    const d = response.data;
    if (d.access_token) {
      const newToken = {
        accessToken: d.access_token,
        refreshToken: d.refresh_token || t.refreshToken,
        expiresAt: Date.now() + (d.expires_in || 7200) * 1000,
        savedAt: new Date().toISOString()
      };
      saveRcsmToken(newToken);
      res.json({ ok: true, expiresAt: new Date(newToken.expiresAt).toISOString() });
    } else {
      res.status(401).json({ error: 'Refresh failed', details: d });
    }
  } catch (error) {
    console.error('RCSM token refresh failed:', error.message);
    res.status(500).json({ error: 'Refresh failed: ' + error.message });
  }
});

router.post('/rcsm-token-clear', requireAuth, requireHmac, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin only' });
  }
  clearRcsmToken();
  res.json({ ok: true, message: 'Token cleared' });
});

module.exports = router;

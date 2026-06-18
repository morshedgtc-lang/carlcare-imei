const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const db = require('../utils/db');
const { SignatureGenerator, extractDeviceDetails, encryptRcsmImei, buildRcsmUrl, parseRcsmResponse, loadRcsmToken, isRcsmTokenValid, RCSM_BASE } = require('../utils/signature');
const { isIpBlocked, recordFailedAttempt } = require('../utils/verify');
const router = express.Router();

const signatureGen = new SignatureGenerator();

function sha256(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}

function ipAllowed(allowedIps, ip) {
  if (!allowedIps) return true;
  const list = allowedIps.split(',').map(s => s.trim());
  return list.includes(ip);
}

router.get('/check-imei', async (req, res) => {
  try {
    if (isIpBlocked(req.ip)) return res.status(403).json({ error: 'IP blocked due to suspicious activity' });

    const apiKey = req.headers['x-api-key'];
    if (!apiKey) return res.status(401).json({ error: 'X-API-Key header required' });

    const keyHash = sha256(apiKey);
    const keyRecord = db.prepare('SELECT * FROM api_keys WHERE key = ? AND active = 1').get(keyHash);
    if (!keyRecord) {
      recordFailedAttempt(req.ip);
      return res.status(401).json({ error: 'Invalid or deactivated API key' });
    }

    if (keyRecord.expires_at && keyRecord.expires_at <= new Date().toISOString().replace('T', ' ').split('.')[0]) {
      return res.status(403).json({ error: 'API key has expired' });
    }

    if (!ipAllowed(keyRecord.allowed_ips, req.ip)) {
      return res.status(403).json({ error: 'IP not allowed for this API key' });
    }

    if (keyRecord.max_requests > 0) {
      const now = new Date().toISOString().replace('T', ' ').split('.')[0];
      if (!keyRecord.requests_reset_at || keyRecord.requests_reset_at < now.split(' ')[0] + ' 00:00:00') {
        db.prepare('UPDATE api_keys SET requests_used = 0, requests_reset_at = ? WHERE id = ?').run(now, keyRecord.id);
        keyRecord.requests_used = 0;
      }
      if (keyRecord.requests_used >= keyRecord.max_requests) {
        return res.status(429).json({ error: 'Daily request limit exceeded' });
      }
    }

    const user = db.prepare('SELECT * FROM users WHERE id = ? AND status = ?').get(keyRecord.user_id, 'active');
    if (!user) return res.status(403).json({ error: 'Account not active' });

    if (user.credits < 1) return res.status(403).json({ error: 'Insufficient credits' });

    const { imei } = req.query;
    if (!imei || !/^\d{15}$/.test(imei)) {
      return res.status(400).json({ error: 'Invalid IMEI. Must be 15 digits.' });
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

    if (keyRecord.max_requests > 0) {
      db.prepare('UPDATE api_keys SET requests_used = requests_used + 1 WHERE id = ?').run(keyRecord.id);
    }
    db.prepare('UPDATE users SET credits = credits - 1 WHERE id = ?').run(user.id);
    db.prepare('INSERT INTO credit_logs (user_id, amount, type, note) VALUES (?, ?, ?, ?)')
      .run(user.id, -1, 'deduct', `API IMEI check: ${imei}`);
    db.prepare('INSERT INTO imei_logs (user_id, api_key_id, imei, response_status, ip) VALUES (?, ?, ?, ?, ?)')
      .run(user.id, keyRecord.id, imei, response.data.code || 0, req.ip);

    if (response.data.code !== 200) {
      return res.status(400).json({ error: response.data.message || 'IMEI lookup failed.' });
    }

    const deviceDetails = extractDeviceDetails(response.data);
    if (!deviceDetails) {
      return res.status(404).json({ error: 'Device information not found.' });
    }

    const remaining = db.prepare('SELECT credits FROM users WHERE id = ?').get(user.id).credits;
    res.json({ success: true, data: deviceDetails, credits_remaining: remaining });

  } catch (error) {
    console.error('API IMEI lookup error:', error.message);
    if (error.response) {
      return res.status(error.response.status).json({ error: error.response.data?.message || error.message });
    }
    if (error.code === 'ECONNABORTED') {
      return res.status(504).json({ error: 'Request timeout' });
    }
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/check-rcsm', async (req, res) => {
  try {
    if (isIpBlocked(req.ip)) return res.status(403).json({ error: 'IP blocked due to suspicious activity' });

    const apiKey = req.headers['x-api-key'];
    if (!apiKey) return res.status(401).json({ error: 'X-API-Key header required' });

    const keyHash = sha256(apiKey);
    const keyRecord = db.prepare('SELECT * FROM api_keys WHERE key = ? AND active = 1').get(keyHash);
    if (!keyRecord) {
      recordFailedAttempt(req.ip);
      return res.status(401).json({ error: 'Invalid or deactivated API key' });
    }

    if (keyRecord.expires_at && keyRecord.expires_at <= new Date().toISOString().replace('T', ' ').split('.')[0]) {
      return res.status(403).json({ error: 'API key has expired' });
    }

    if (!ipAllowed(keyRecord.allowed_ips, req.ip)) {
      return res.status(403).json({ error: 'IP not allowed for this API key' });
    }

    if (keyRecord.max_requests > 0) {
      const now = new Date().toISOString().replace('T', ' ').split('.')[0];
      if (!keyRecord.requests_reset_at || keyRecord.requests_reset_at < now.split(' ')[0] + ' 00:00:00') {
        db.prepare('UPDATE api_keys SET requests_used = 0, requests_reset_at = ? WHERE id = ?').run(now, keyRecord.id);
        keyRecord.requests_used = 0;
      }
      if (keyRecord.requests_used >= keyRecord.max_requests) {
        return res.status(429).json({ error: 'Daily request limit exceeded' });
      }
    }

    const user = db.prepare('SELECT * FROM users WHERE id = ? AND status = ?').get(keyRecord.user_id, 'active');
    if (!user) return res.status(403).json({ error: 'Account not active' });

    if (user.credits < 1) return res.status(403).json({ error: 'Insufficient credits' });

    const { imei } = req.query;
    if (!imei || !/^\d{15}$/.test(imei)) {
      return res.status(400).json({ error: 'Invalid IMEI. Must be 15 digits.' });
    }

    const tokenData = loadRcsmToken();
    if (!tokenData || !tokenData.accessToken) {
      return res.status(503).json({ error: 'RCSM token not configured' });
    }
    if (!isRcsmTokenValid()) {
      return res.status(503).json({ error: 'RCSM token expired' });
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

    if (keyRecord.max_requests > 0) {
      db.prepare('UPDATE api_keys SET requests_used = requests_used + 1 WHERE id = ?').run(keyRecord.id);
    }
    db.prepare('UPDATE users SET credits = credits - 1 WHERE id = ?').run(user.id);
    db.prepare('INSERT INTO credit_logs (user_id, amount, type, note) VALUES (?, ?, ?, ?)')
      .run(user.id, -1, 'deduct', `RCSM API IMEI check: ${imei}`);
    db.prepare('INSERT INTO imei_logs (user_id, api_key_id, imei, response_status, ip) VALUES (?, ?, ?, ?, ?)')
      .run(user.id, keyRecord.id, imei, response.data.ErrorCode === 0 ? 200 : 0, req.ip);

    const deviceDetails = parseRcsmResponse(response.data);
    if (!deviceDetails) {
      return res.status(404).json({ error: 'Device information not found' });
    }

    const remaining = db.prepare('SELECT credits FROM users WHERE id = ?').get(user.id).credits;
    res.json({ success: true, data: deviceDetails, credits_remaining: remaining });

  } catch (error) {
    console.error('RCSM API IMEI lookup error:', error.message);
    if (error.response) {
      return res.status(error.response.status).json({ error: error.response.data?.Message || error.message });
    }
    if (error.code === 'ECONNABORTED') {
      return res.status(504).json({ error: 'RCSM request timeout' });
    }
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;

const crypto = require('crypto');
const db = require('./db');

const failCounts = {};

function sha256(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}

function verifyHmac(req, userId) {
  const sign = req.headers['x-request-sign'];
  const timestamp = req.headers['x-timestamp'];
  if (!sign || !timestamp) return false;
  const diff = Date.now() - Number(timestamp);
  if (diff < 0 || diff > 30000) return false;
  const keyRec = db.prepare("SELECT key FROM session_keys WHERE user_id = ? AND expires_at > datetime('now') ORDER BY created_at DESC LIMIT 1").get(userId);
  if (!keyRec) return false;
  let body = '';
  if (req.body && typeof req.body === 'object') {
    const json = JSON.stringify(req.body);
    body = json === '{}' ? '' : json;
  } else if (req.body) {
    body = String(req.body);
  }
  const fullPath = req.originalUrl.split('?')[0];
  const expected = sha256(keyRec.key + req.method + fullPath + body + timestamp);
  return expected === sign;
}

function isIpBlocked(ip) {
  const rec = db.prepare("SELECT id FROM blocked_ips WHERE ip = ? AND blocked_until > datetime('now')").get(ip);
  return !!rec;
}

function recordFailedAttempt(ip) {
  const now = Date.now();
  if (!failCounts[ip]) failCounts[ip] = [];
  failCounts[ip] = failCounts[ip].filter(t => now - t < 3600000);
  failCounts[ip].push(now);
  const total = failCounts[ip].length;
  const recent5min = failCounts[ip].filter(t => now - t < 300000).length;
  if (recent5min >= 15) {
    blockIp(ip, 30, '15 failed attempts in 5 min');
  } else if (total >= 50) {
    blockIp(ip, 1440, '50 failed attempts in 1 hour');
  } else if (total >= 100) {
    blockIp(ip, 999999, '100 total failed attempts');
  }
}

function blockIp(ip, minutes, reason) {
  const existing = db.prepare("SELECT id FROM blocked_ips WHERE ip = ? AND blocked_until > datetime('now')").get(ip);
  if (existing) return;
  const until = new Date(Date.now() + minutes * 60000).toISOString().replace('T', ' ').split('.')[0];
  db.prepare("INSERT INTO blocked_ips (ip, blocked_until, reason) VALUES (?, ?, ?)").run(ip, until, reason);
}

function requireHmac(req, res, next) {
  if (isIpBlocked(req.ip)) return res.status(403).json({ error: 'IP blocked due to suspicious activity' });
  if (!verifyHmac(req, req.user.id)) {
    recordFailedAttempt(req.ip);
    return res.status(401).json({ error: 'Invalid request signature' });
  }
  next();
}

function cleanupExpired() {
  try {
    db.exec("DELETE FROM session_keys WHERE expires_at <= datetime('now')");
    db.exec("DELETE FROM blocked_ips WHERE blocked_until <= datetime('now')");
  } catch(e) {}
}

const initCleanup = () => {
  cleanupExpired();
  setInterval(cleanupExpired, 300000);
};

const { initPromise } = require('./db');
initPromise.then(initCleanup).catch(() => setTimeout(initCleanup, 3000));

module.exports = { verifyHmac, isIpBlocked, recordFailedAttempt, requireHmac, sha256 };
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const db = require('../utils/db');
const { isIpBlocked, recordFailedAttempt } = require('../utils/verify');
const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-in-production';

router.post('/register', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Name, email, and password are required' });
  }
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Invalid email format' });
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) return res.status(409).json({ error: 'Email already registered' });
  const hash = bcrypt.hashSync(password, 10);
  db.prepare('INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)').run(name, email, hash);
  res.json({ message: 'Registration submitted. Awaiting admin approval.' });
});

router.post('/login', (req, res) => {
  try {
    if (isIpBlocked(req.ip)) return res.status(403).json({ error: 'IP blocked. Try again later.' });
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    if (!bcrypt.compareSync(password, user.password_hash)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    if (user.status !== 'active') {
      return res.status(403).json({ error: 'Account not yet approved by admin' });
    }
    db.exec("DELETE FROM session_keys WHERE user_id = ? OR expires_at <= datetime('now')");
    db.prepare("DELETE FROM blocked_ips WHERE ip = ?").run(req.ip);
    const sessionKey = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 3600000).toISOString().replace('T', ' ').split('.')[0];
    db.prepare('INSERT INTO session_keys (user_id, key, expires_at) VALUES (?, ?, ?)').run(user.id, sessionKey, expiresAt);
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role, name: user.name },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    res.json({ token, session_key: sessionKey, expires_in: 3600, user: { id: user.id, name: user.name, email: user.email, role: user.role, credits: user.credits } });
  } catch(e) {
    console.error('LOGIN ERROR:', e.message);
    res.status(500).json({ error: 'Login failed' });
  }
});

router.get('/me', (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'No token' });
  try {
    const decoded = jwt.verify(auth.replace('Bearer ', ''), JWT_SECRET);
    const user = db.prepare('SELECT id, name, email, role, status, credits FROM users WHERE id = ?').get(decoded.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const existing = db.prepare("SELECT key FROM session_keys WHERE user_id = ? AND expires_at > datetime('now') ORDER BY created_at DESC LIMIT 1").get(user.id);
    let sessionKey = null;
    if (existing) {
      sessionKey = existing.key;
    } else {
      sessionKey = crypto.randomBytes(32).toString('hex');
      const expiresAt = new Date(Date.now() + 3600000).toISOString().replace('T', ' ').split('.')[0];
      db.prepare('INSERT INTO session_keys (user_id, key, expires_at) VALUES (?, ?, ?)').run(user.id, sessionKey, expiresAt);
    }
    res.json({ user, session_key: sessionKey });
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
});

router.post('/logout', (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.json({ message: 'Logged out' });
  try {
    const decoded = jwt.verify(auth.replace('Bearer ', ''), JWT_SECRET);
    db.exec("DELETE FROM session_keys WHERE user_id = ? OR expires_at <= datetime('now')");
    res.json({ message: 'Logged out' });
  } catch { res.json({ message: 'Logged out' }); }
});

router.post('/change-password', (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'No token' });
  try {
    const decoded = jwt.verify(auth.replace('Bearer ', ''), JWT_SECRET);
    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword) {
      return res.status(400).json({ error: 'Old and new password required' });
    }
    if (newPassword.length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters' });
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(decoded.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (!bcrypt.compareSync(oldPassword, user.password_hash)) {
      return res.status(403).json({ error: 'Current password is incorrect' });
    }
    const hash = bcrypt.hashSync(newPassword, 10);
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, decoded.id);
    res.json({ message: 'Password changed successfully' });
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
});

module.exports = router;
module.exports.JWT_SECRET = JWT_SECRET;

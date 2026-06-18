const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
const db = require('../utils/db');
const { JWT_SECRET } = require('./auth');
const router = express.Router();

const requireAdmin = (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'No token' });
  try {
    const decoded = jwt.verify(auth.replace('Bearer ', ''), JWT_SECRET);
    if (decoded.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
};
router.use(requireAdmin);

router.get('/users', (req, res) => {
  const users = db.prepare('SELECT id, name, email, role, status, credits, created_at FROM users ORDER BY created_at DESC').all();
  res.json(users);
});

router.post('/users/:id/approve', (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  db.prepare('UPDATE users SET status = ? WHERE id = ?').run('active', req.params.id);
  db.prepare('INSERT INTO credit_logs (user_id, amount, type, note) VALUES (?, ?, ?, ?)')
    .run(req.params.id, 0, 'system', 'Account approved');
  res.json({ message: 'User approved' });
});

router.post('/users/:id/suspend', (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  db.prepare('UPDATE users SET status = ? WHERE id = ?').run('suspended', req.params.id);
  res.json({ message: 'User suspended' });
});

router.post('/users/:id/credits', (req, res) => {
  const { amount, note } = req.body;
  if (amount === undefined || amount === null || !Number.isInteger(amount) || amount < 1) {
    return res.status(400).json({ error: 'Amount must be a positive integer' });
  }
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  db.prepare('UPDATE users SET credits = credits + ? WHERE id = ?').run(amount, req.params.id);
  db.prepare('INSERT INTO credit_logs (user_id, amount, type, note) VALUES (?, ?, ?, ?)')
    .run(req.params.id, amount, amount > 0 ? 'add' : 'deduct', note || `${amount > 0 ? 'Added' : 'Deducted'} by admin`);
  const updated = db.prepare('SELECT credits FROM users WHERE id = ?').get(req.params.id);
  res.json({ message: 'Credits updated', credits: updated.credits });
});

router.post('/users/:id/credits/deduct', (req, res) => {
  const { amount, note } = req.body;
  if (amount === undefined || amount === null || !Number.isInteger(amount) || amount < 1) {
    return res.status(400).json({ error: 'Amount must be a positive integer' });
  }
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.credits < amount) return res.status(400).json({ error: 'Insufficient credits to deduct' });
  const deduct = -amount;
  db.prepare('UPDATE users SET credits = credits + ? WHERE id = ?').run(deduct, req.params.id);
  db.prepare('INSERT INTO credit_logs (user_id, amount, type, note) VALUES (?, ?, ?, ?)')
    .run(req.params.id, deduct, 'deduct', note || 'Deducted by admin');
  const updated = db.prepare('SELECT credits FROM users WHERE id = ?').get(req.params.id);
  res.json({ message: 'Credits deducted', credits: updated.credits });
});

router.get('/users/:id/history', (req, res) => {
  const user = db.prepare('SELECT id, name, email FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const checks = db.prepare('SELECT * FROM imei_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 100').all(req.params.id);
  const totalChecks = db.prepare('SELECT COUNT(*) as count FROM imei_logs WHERE user_id = ?').get(req.params.id).count;
  const totalCreditsUsed = db.prepare("SELECT COALESCE(SUM(ABS(amount)), 0) as total FROM credit_logs WHERE user_id = ? AND type = 'deduct'").get(req.params.id).total;
  res.json({ user, checks, totalChecks, totalCreditsUsed });
});

router.post('/users/create', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Name, email, and password required' });
  }
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) return res.status(409).json({ error: 'Email already exists' });
  const bcrypt = require('bcryptjs');
  const hash = bcrypt.hashSync(password, 10);
  const result = db.prepare('INSERT INTO users (name, email, password_hash, status, credits) VALUES (?, ?, ?, ?, ?)').run(name, email, hash, 'active', 0);
  db.prepare('INSERT INTO credit_logs (user_id, amount, type, note) VALUES (?, ?, ?, ?)').run(result.lastInsertRowid, 0, 'system', 'Account created by admin');
  const user = db.prepare('SELECT id, name, email, role, status, credits FROM users WHERE id = ?').get(result.lastInsertRowid);
  res.json({ message: 'User created', user });
});

router.get('/logs', (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 50;
  const offset = (page - 1) * limit;
  const logs = db.prepare(`
    SELECT il.*, u.name AS user_name, u.email AS user_email
    FROM imei_logs il
    LEFT JOIN users u ON u.id = il.user_id
    ORDER BY il.created_at DESC LIMIT ? OFFSET ?
  `).all(limit, offset);
  const total = db.prepare('SELECT COUNT(*) as count FROM imei_logs').get().count;
  res.json({ logs, total, page, limit });
});

router.post('/api-keys', (req, res) => {
  const { user_id, label, allowed_ips, expires_in_days, max_requests } = req.body;
  if (!user_id) return res.status(400).json({ error: 'user_id is required' });
  const user = db.prepare('SELECT id FROM users WHERE id = ?').get(user_id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const raw = crypto.randomBytes(24).toString('hex');
  const key = 'sk_live_' + raw;
  const hash = crypto.createHash('sha256').update(key).digest('hex');
  let expires_at = null;
  if (expires_in_days && expires_in_days > 0) {
    const d = new Date(Date.now() + expires_in_days * 86400000);
    expires_at = d.toISOString().replace('T', ' ').split('.')[0];
  }
  db.prepare('INSERT INTO api_keys (user_id, key, label, expires_at, max_requests, allowed_ips) VALUES (?, ?, ?, ?, ?, ?)')
    .run(user_id, hash, label || 'Default', expires_at, max_requests || 0, allowed_ips || null);
  res.json({ message: 'API key created', key, user_id, label: label || 'Default', expires_at, max_requests: max_requests || 0, allowed_ips: allowed_ips || null });
});

router.get('/api-keys', (req, res) => {
  const keys = db.prepare(`
    SELECT ak.id, ak.user_id, u.name AS user_name, u.email AS user_email, ak.label, ak.active,
           ak.expires_at, ak.max_requests, ak.requests_used, ak.allowed_ips, ak.created_at
    FROM api_keys ak LEFT JOIN users u ON u.id = ak.user_id ORDER BY ak.created_at DESC
  `).all();
  res.json({ keys });
});

router.get('/clients', (req, res) => {
  const query = req.query.q || '';
  let users;
  if (query) {
    users = db.prepare("SELECT id, name, email, status, credits, created_at FROM users WHERE role = 'client' AND (name LIKE ? OR email LIKE ?) ORDER BY created_at DESC").all(`%${query}%`, `%${query}%`);
  } else {
    users = db.prepare("SELECT id, name, email, status, credits, created_at FROM users WHERE role = 'client' ORDER BY created_at DESC").all();
  }
  res.json({ users, total: users.length });
});

router.get('/settings', (req, res) => {
  const settings = db.prepare('SELECT key, value FROM settings').all();
  const obj = {};
  settings.forEach(s => obj[s.key] = s.value);
  res.json(obj);
});

router.post('/settings', (req, res) => {
  const entries = req.body;
  if (!entries || typeof entries !== 'object') return res.status(400).json({ error: 'Settings object required' });
  Object.keys(entries).forEach(key => {
    const existing = db.prepare('SELECT id FROM settings WHERE key = ?').get(key);
    if (existing) {
      db.prepare("UPDATE settings SET value = ?, updated_at = datetime('now') WHERE key = ?").run(String(entries[key]), key);
    } else {
      db.prepare("INSERT INTO settings (key, value) VALUES (?, ?)").run(key, String(entries[key]));
    }
  });
  res.json({ message: 'Settings saved' });
});

router.get('/prices', (req, res) => {
  const prices = db.prepare('SELECT * FROM prices ORDER BY id').all();
  res.json({ prices });
});

router.post('/prices', (req, res) => {
  const { name, cost, currency } = req.body;
  if (!name || !cost) return res.status(400).json({ error: 'Name and cost required' });
  const existing = db.prepare('SELECT id FROM prices WHERE name = ?').get(name);
  if (existing) {
    db.prepare('UPDATE prices SET cost = ?, currency = ? WHERE name = ?').run(cost, currency || 'USD', name);
  } else {
    db.prepare('INSERT INTO prices (name, cost, currency) VALUES (?, ?, ?)').run(name, cost, currency || 'USD');
  }
  res.json({ message: 'Price saved' });
});

router.get('/currencies', (req, res) => {
  const currencies = db.prepare('SELECT * FROM currencies ORDER BY code').all();
  res.json({ currencies });
});

router.post('/currencies', (req, res) => {
  const { code, name, symbol, rate } = req.body;
  if (!code || !name) return res.status(400).json({ error: 'Code and name required' });
  const existing = db.prepare('SELECT id FROM currencies WHERE code = ?').get(code.toUpperCase());
  if (existing) {
    db.prepare('UPDATE currencies SET name = ?, symbol = ?, rate = ? WHERE code = ?').run(name, symbol || '$', rate || 1.0, code.toUpperCase());
  } else {
    db.prepare('INSERT INTO currencies (code, name, symbol, rate) VALUES (?, ?, ?, ?)').run(code.toUpperCase(), name, symbol || '$', rate || 1.0);
  }
  res.json({ message: 'Currency saved' });
});

router.get('/credit-logs', (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 50;
  const offset = (page - 1) * limit;
  const logs = db.prepare(`
    SELECT cl.*, u.name AS user_name, u.email AS user_email
    FROM credit_logs cl
    LEFT JOIN users u ON u.id = cl.user_id
    ORDER BY cl.created_at DESC LIMIT ? OFFSET ?
  `).all(limit, offset);
  const total = db.prepare('SELECT COUNT(*) as count FROM credit_logs').get().count;
  res.json({ logs, total, page, limit });
});

router.get('/services', (req, res) => {
  const services = db.prepare('SELECT * FROM services ORDER BY id').all();
  res.json({ services });
});

router.post('/services', (req, res) => {
  const { name, description, active, cost } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });
  const existing = db.prepare('SELECT id FROM services WHERE name = ?').get(name);
  if (existing) {
    db.prepare('UPDATE services SET description = ?, active = ?, cost = ? WHERE id = ?').run(description || '', active !== undefined ? (active ? 1 : 0) : 1, cost || 0, existing.id);
    res.json({ message: 'Service updated', id: existing.id });
  } else {
    const r = db.prepare('INSERT INTO services (name, description, active, cost) VALUES (?, ?, ?, ?)').run(name, description || '', active !== undefined ? (active ? 1 : 0) : 1, cost || 0);
    res.json({ message: 'Service created', id: r.lastInsertRowid });
  }
});

router.post('/services/:id/fields', (req, res) => {
  const { fields } = req.body;
  if (!Array.isArray(fields)) return res.status(400).json({ error: 'fields array required' });
  const service = db.prepare('SELECT id FROM services WHERE id = ?').get(req.params.id);
  if (!service) return res.status(404).json({ error: 'Service not found' });
  db.prepare('DELETE FROM service_fields WHERE service_id = ?').run(req.params.id);
  const insert = db.prepare('INSERT INTO service_fields (service_id, label, field_type, required, sort_order) VALUES (?, ?, ?, ?, ?)');
  fields.forEach((f, i) => {
    insert.run(req.params.id, f.label, f.field_type || 'text', f.required ? 1 : 0, i);
  });
  res.json({ message: 'Fields saved' });
});

router.get('/orders', (req, res) => {
  const { status, user_id, service_id, page: p } = req.query;
  const page = parseInt(p) || 1;
  const limit = 50;
  const offset = (page - 1) * limit;
  let where = 'WHERE 1=1';
  const params = [];
  if (status) { where += ' AND o.status = ?'; params.push(status); }
  if (user_id) { where += ' AND o.user_id = ?'; params.push(user_id); }
  if (service_id) { where += ' AND o.service_id = ?'; params.push(service_id); }
  const total = db.prepare(`SELECT COUNT(*) as count FROM orders o ${where}`).get(...params).count;
  const orders = db.prepare(`
    SELECT o.id, o.user_id, u.name AS user_name, u.email AS user_email,
           o.service_id, s.name AS service_name, o.status,
           o.admin_reply, o.unlock_code, o.created_at, o.updated_at
    FROM orders o
    LEFT JOIN users u ON u.id = o.user_id
    LEFT JOIN services s ON s.id = o.service_id
    ${where} ORDER BY o.created_at DESC LIMIT ? OFFSET ?
  `).all(...params, limit, offset);
  res.json({ orders, total, page });
});

router.get('/orders/:id', (req, res) => {
  const order = db.prepare(`
    SELECT o.*, u.name AS user_name, u.email AS user_email, s.name AS service_name, s.cost AS service_cost
    FROM orders o LEFT JOIN users u ON u.id = o.user_id LEFT JOIN services s ON s.id = o.service_id
    WHERE o.id = ?
  `).get(req.params.id);
  if (!order) return res.status(404).json({ error: 'Order not found' });
  const data = db.prepare(`
    SELECT od.id, od.value, sf.label, sf.field_type
    FROM order_data od LEFT JOIN service_fields sf ON sf.id = od.field_id
    WHERE od.order_id = ?
  `).all(order.id);
  res.json({ order, data });
});

router.post('/orders/:id/accept', (req, res) => {
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(req.params.id);
  if (!order) return res.status(404).json({ error: 'Order not found' });
  if (order.status !== 'pending') return res.status(400).json({ error: 'Only pending orders can be accepted' });
  db.prepare("UPDATE orders SET status = 'processing', updated_at = datetime('now') WHERE id = ?").run(req.params.id);
  res.json({ message: 'Order accepted', status: 'processing' });
});

router.post('/orders/:id/reject', (req, res) => {
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(req.params.id);
  if (!order) return res.status(404).json({ error: 'Order not found' });
  if (order.status !== 'pending') return res.status(400).json({ error: 'Only pending orders can be rejected' });
  const { admin_reply } = req.body;
  db.prepare("UPDATE orders SET status = 'rejected', admin_reply = ?, updated_at = datetime('now') WHERE id = ?").run(admin_reply || '', req.params.id);
  res.json({ message: 'Order rejected', status: 'rejected' });
});

router.post('/orders/:id/reply', (req, res) => {
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(req.params.id);
  if (!order) return res.status(404).json({ error: 'Order not found' });
  const { admin_reply } = req.body;
  db.prepare('UPDATE orders SET admin_reply = ?, updated_at = datetime(\'now\') WHERE id = ?').run(admin_reply || '', req.params.id);
  res.json({ message: 'Reply saved' });
});

router.post('/orders/:id/complete', (req, res) => {
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(req.params.id);
  if (!order) return res.status(404).json({ error: 'Order not found' });
  if (order.status !== 'processing') return res.status(400).json({ error: 'Only processing orders can be completed' });
  const { unlock_code, admin_reply } = req.body;
  db.prepare("UPDATE orders SET status = 'completed', unlock_code = ?, admin_reply = ?, updated_at = datetime('now') WHERE id = ?")
    .run(unlock_code || '', admin_reply || '', req.params.id);
  res.json({ message: 'Order completed', status: 'completed' });
});

router.post('/orders/bulk-reply', (req, res) => {
  const { ids, admin_reply } = req.body;
  if (!Array.isArray(ids) || ids.length === 0) return res.status(400).json({ error: 'ids array required' });
  const update = db.prepare("UPDATE orders SET admin_reply = ?, updated_at = datetime('now') WHERE id = ?");
  ids.forEach(id => update.run(admin_reply || '', id));
  res.json({ message: 'Bulk reply sent', count: ids.length });
});

// POST /api/admin/seed — (Re)seed demo data on demand
router.post('/seed', requireAdmin, (req, res) => {
  const db2 = require('../utils/db');
  const { DEMO_SERVICES, seedDemoData } = db2;
  if (typeof seedDemoData === 'function') {
    // force re-create demo user and services even if they exist
    const demoUser = db2.prepare("SELECT id FROM users WHERE email = 'demo@demo.com'").get();
    if (!demoUser) {
      const bcrypt = require('bcryptjs');
      const hash = bcrypt.hashSync('demo123', 10);
      db2.prepare("INSERT INTO users (name, email, password_hash, role, status, credits) VALUES (?, ?, ?, ?, ?, ?)")
        .run('Demo User', 'demo@demo.com', hash, 'client', 'active', 100);
    }
    // delete existing services and recreate
    db2.exec("DELETE FROM order_data");
    db2.exec("DELETE FROM orders");
    db2.exec("DELETE FROM service_fields");
    db2.exec("DELETE FROM services");
    DEMO_SERVICES.forEach(s => {
      const r = db2.prepare("INSERT INTO services (name, description, active, cost) VALUES (?, ?, 1, ?)").run(s.name, s.description, s.cost);
      const svcId = r.lastInsertRowid;
      s.fields.forEach((f, i) => {
        db2.prepare("INSERT INTO service_fields (service_id, label, field_type, required, sort_order) VALUES (?, ?, ?, ?, ?)")
          .run(svcId, f.label, f.type, f.req ? 1 : 0, i);
      });
    });
    const { save } = db2;
    if (typeof save === 'function') save();
    res.json({ message: 'Demo data seeded: demo@demo.com / demo123 (100 credits), 5 services' });
  } else {
    res.status(500).json({ error: 'seedDemoData not available' });
  }
});

module.exports = router;

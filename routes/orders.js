const express = require('express');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const db = require('../utils/db');
const { JWT_SECRET } = require('./auth');
const router = express.Router();

const requireAuth = (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'No token' });
  try {
    const decoded = jwt.verify(auth.replace('Bearer ', ''), JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
};

const uploadDir = path.join(__dirname, '..', 'uploads', 'orders');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, unique + path.extname(file.originalname));
  }
});
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });

router.use(requireAuth);

router.get('/services', (req, res) => {
  const services = db.prepare("SELECT id, name, description, cost FROM services WHERE active = 1 ORDER BY id").all();
  res.json({ services });
});

router.get('/services/:id/fields', (req, res) => {
  const service = db.prepare("SELECT id, name, description, cost FROM services WHERE id = ? AND active = 1").get(req.params.id);
  if (!service) return res.status(404).json({ error: 'Service not found' });
  const fields = db.prepare("SELECT id, label, field_type, required, sort_order FROM service_fields WHERE service_id = ? ORDER BY sort_order").all(req.params.id);
  res.json({ service, fields });
});

router.post('/', upload.any(), (req, res) => {
  const { service_id } = req.body;
  if (!service_id) return res.status(400).json({ error: 'service_id required' });
  const service = db.prepare("SELECT * FROM services WHERE id = ? AND active = 1").get(service_id);
  if (!service) return res.status(404).json({ error: 'Service not found' });
  const fields = db.prepare("SELECT * FROM service_fields WHERE service_id = ?").all(service_id);
  if (fields.length === 0) return res.status(400).json({ error: 'No fields defined for this service' });

  const result = db.prepare("INSERT INTO orders (user_id, service_id, status) VALUES (?, ?, 'pending')").run(req.user.id, service_id);
  const orderId = result.lastInsertRowid;

  const files = req.files || [];
  const fileMap = {};
  files.forEach(f => {
    const match = f.fieldname.match(/^file_(\d+)$/);
    if (match) fileMap[match[1]] = '/uploads/orders/' + f.filename;
  });

  const insert = db.prepare("INSERT INTO order_data (order_id, field_id, value) VALUES (?, ?, ?)");
  fields.forEach(f => {
    const val = req.body['field_' + f.id];
    const fileVal = fileMap[f.id];
    const value = fileVal || val || '';
    if (f.required && !value) {
      db.prepare("DELETE FROM orders WHERE id = ?").run(orderId);
      return res.status(400).json({ error: f.label + ' is required' });
      return res.status(400).json({ error: f.label + ' is required' });
    }
    insert.run(orderId, f.id, value);
  });

  res.json({ message: 'Order submitted', order_id: orderId, status: 'pending' });
});

router.get('/', (req, res) => {
  const orders = db.prepare(`
    SELECT o.id, o.status, o.admin_reply, o.unlock_code, o.created_at, o.updated_at,
           s.name AS service_name
    FROM orders o LEFT JOIN services s ON s.id = o.service_id
    WHERE o.user_id = ? ORDER BY o.created_at DESC
  `).all(req.user.id);
  res.json({ orders });
});

router.get('/:id', (req, res) => {
  const order = db.prepare(`
    SELECT o.*, s.name AS service_name, s.description AS service_desc, s.cost AS service_cost
    FROM orders o LEFT JOIN services s ON s.id = o.service_id
    WHERE o.id = ? AND o.user_id = ?
  `).get(req.params.id, req.user.id);
  if (!order) return res.status(404).json({ error: 'Order not found' });
  const data = db.prepare(`
    SELECT od.id, od.value, sf.label, sf.field_type
    FROM order_data od LEFT JOIN service_fields sf ON sf.id = od.field_id
    WHERE od.order_id = ?
  `).all(order.id);
  res.json({ order, data });
});

module.exports = router;

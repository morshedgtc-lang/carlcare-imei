require('dotenv').config();
const express = require('express');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const path = require('path');

const imeiRoutes = require('./routes/imei');
const authRoutes = require('./routes/auth');
const adminRoutes = require('./routes/admin');
const apiRoutes = require('./routes/api');
const ordersRoutes = require('./routes/orders');

const app = express();
const PORT = process.env.PORT || 3000;

// Trust proxy before rate-limit middleware to properly handle X-Forwarded-For header
app.set('trust proxy', 1);

app.use(helmet({
  crossOriginResourcePolicy: false,
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "blob:"],
      mediaSrc: ["'self'"],
      connectSrc: ["'self'"],
    }
  }
}));
app.use(express.json({ limit: '1mb' }));
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500,
  message: { success: false, error: 'Too many requests. Please try again later.' }
});
app.use('/api/', limiter);

app.use('/api/auth', authRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/imei', imeiRoutes);
app.use('/api/orders', ordersRoutes);
app.use('/api/v1', apiRoutes);

app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'), err => {
    if (err) res.status(404).json({ error: 'Not found' });
  });
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ success: false, error: 'Internal server error.' });
});

const { initPromise } = require('./utils/db');
const { loadRcsmToken, saveRcsmToken, RCSM_BASE } = require('./utils/signature');

let rcsmRefreshTimer = null;

function scheduleRcsmRefresh() {
  if (rcsmRefreshTimer) clearTimeout(rcsmRefreshTimer);
  const t = loadRcsmToken();
  if (!t || !t.refreshToken) return;
  const msLeft = (t.expiresAt || 0) - Date.now();
  const refreshIn = Math.max(msLeft - 10 * 60 * 1000, 30 * 1000);
  rcsmRefreshTimer = setTimeout(async () => {
    try {
      const axios = require('axios');
      const response = await axios.post(RCSM_BASE + '/token',
        `grant_type=refresh_token&refresh_token=${encodeURIComponent(t.refreshToken)}`,
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 10000 }
      );
      const d = response.data;
      if (d.access_token) {
        saveRcsmToken({
          accessToken: d.access_token,
          refreshToken: d.refresh_token || t.refreshToken,
          expiresAt: Date.now() + (d.expires_in || 7200) * 1000,
          savedAt: new Date().toISOString()
        });
        console.log('RCSM token refreshed successfully');
        scheduleRcsmRefresh();
      }
    } catch (e) {
      console.log('RCSM token refresh failed:', e.message);
    }
  }, refreshIn);
}

initPromise.then(() => {
  scheduleRcsmRefresh();
  const t = loadRcsmToken();
  if (t && t.accessToken) {
    console.log('RCSM token loaded, expires in', Math.max(0, Math.round(((t.expiresAt || 0) - Date.now()) / 60000)), 'minutes');
  }
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}).catch(err => {
  console.error('Database init failed:', err);
  process.exit(1);
});

module.exports = app;

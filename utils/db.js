const initSqlJs = require('sql.js');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');

const DB_PATH = path.join(__dirname, '..', 'data', 'carlcare.db');
const dataDir = path.dirname(DB_PATH);
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

let db = null;
let SQL = null;

function save() {
  if (!db) return;
  fs.writeFileSync(DB_PATH, Buffer.from(db.export()));
}

function esc(v) {
  if (v === null || v === undefined) return 'NULL';
  if (typeof v === 'number') return v;
  return "'" + String(v).replace(/'/g, "''") + "'";
}

const api = {
  prepare(sql) {
    return {
      get(...params) {
        const fullSql = params.length
          ? sql.replace(/\?/g, () => esc(params.shift()))
          : sql;
        const r = db.exec(fullSql);
        if (!r.length || !r[0].values.length) return undefined;
        const row = r[0].values[0];
        const obj = {};
        r[0].columns.forEach((c, i) => { obj[c] = row[i]; });
        return obj;
      },
      all(...params) {
        const fullSql = params.length
          ? sql.replace(/\?/g, () => esc(params.shift()))
          : sql;
        const r = db.exec(fullSql);
        if (!r.length) return [];
        return r[0].values.map(row => {
          const obj = {};
          r[0].columns.forEach((c, i) => { obj[c] = row[i]; });
          return obj;
        });
      },
      run(...params) {
        const fullSql = params.length
          ? sql.replace(/\?/g, () => esc(params.shift()))
          : sql;
        db.run(fullSql);
        const rowidR = db.exec('SELECT last_insert_rowid() AS id');
        const rowid = rowidR.length ? rowidR[0].values[0][0] : null;
        save();
        const changes = db.getRowsModified();
        return { changes, lastInsertRowid: rowid };
      }
    };
  },
  exec(sql) {
    db.run(sql);
    save();
  }
};

async function init() {
  try {
    SQL = await initSqlJs();
  } catch(e) {
    console.error('DB init failed:', e.message);
    throw e;
  }
  if (fs.existsSync(DB_PATH)) {
    db = new SQL.Database(fs.readFileSync(DB_PATH));
  } else {
    db = new SQL.Database();
  }
  db.run('PRAGMA foreign_keys = ON');
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'client',
      status TEXT NOT NULL DEFAULT 'pending',
      credits INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS api_keys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id),
      key TEXT UNIQUE NOT NULL,
      label TEXT NOT NULL DEFAULT 'Default',
      active INTEGER NOT NULL DEFAULT 1,
      expires_at TEXT,
      max_requests INTEGER NOT NULL DEFAULT 0,
      requests_used INTEGER NOT NULL DEFAULT 0,
      requests_reset_at TEXT,
      allowed_ips TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);
  try { db.run("ALTER TABLE api_keys ADD COLUMN expires_at TEXT"); } catch(e) {}
  try { db.run("ALTER TABLE api_keys ADD COLUMN max_requests INTEGER NOT NULL DEFAULT 0"); } catch(e) {}
  try { db.run("ALTER TABLE api_keys ADD COLUMN requests_used INTEGER NOT NULL DEFAULT 0"); } catch(e) {}
  try { db.run("ALTER TABLE api_keys ADD COLUMN requests_reset_at TEXT"); } catch(e) {}
  try { db.run("ALTER TABLE api_keys ADD COLUMN allowed_ips TEXT"); } catch(e) {}
  db.run(`
    CREATE TABLE IF NOT EXISTS session_keys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id),
      key TEXT UNIQUE NOT NULL,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS blocked_ips (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ip TEXT NOT NULL,
      blocked_until TEXT NOT NULL,
      reason TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS imei_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER REFERENCES users(id),
      api_key_id INTEGER REFERENCES api_keys(id),
      imei TEXT NOT NULL,
      response_status INTEGER NOT NULL DEFAULT 0,
      ip TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS credit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id),
      amount INTEGER NOT NULL,
      type TEXT NOT NULL,
      note TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS settings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      key TEXT UNIQUE NOT NULL,
      value TEXT,
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS prices (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      cost INTEGER NOT NULL DEFAULT 1,
      currency TEXT NOT NULL DEFAULT 'USD',
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS currencies (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      code TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      symbol TEXT NOT NULL DEFAULT '$',
      rate REAL NOT NULL DEFAULT 1.0,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS services (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT,
      cost INTEGER NOT NULL DEFAULT 0,
      active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);
  try { db.run("ALTER TABLE services ADD COLUMN cost INTEGER NOT NULL DEFAULT 0"); } catch(e) {}
  db.run(`
    CREATE TABLE IF NOT EXISTS service_fields (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      service_id INTEGER NOT NULL REFERENCES services(id),
      label TEXT NOT NULL,
      field_type TEXT NOT NULL DEFAULT 'text',
      required INTEGER NOT NULL DEFAULT 1,
      sort_order INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id),
      service_id INTEGER NOT NULL REFERENCES services(id),
      status TEXT NOT NULL DEFAULT 'pending',
      admin_reply TEXT,
      unlock_code TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS order_data (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      order_id INTEGER NOT NULL REFERENCES orders(id),
      field_id INTEGER NOT NULL REFERENCES service_fields(id),
      value TEXT
    )
  `);
  db.exec("INSERT OR IGNORE INTO settings (key, value) VALUES ('service_enabled', '1'), ('per_check_cost', '1'), ('maintenance_msg', '')");
  db.exec("INSERT OR IGNORE INTO currencies (code, name, symbol, rate) VALUES ('USD', 'US Dollar', '$', 1.0), ('BDT', 'Bangladeshi Taka', '৳', 110.0), ('INR', 'Indian Rupee', '₹', 83.0), ('NGN', 'Nigerian Naira', '₦', 1500.0)");
  db.exec("INSERT OR IGNORE INTO prices (name, cost, currency) VALUES ('IMEI Check', 1, 'USD')");
  const existing = api.prepare("SELECT id FROM users WHERE role = 'admin'").get();
  if (!existing) {
    const hash = bcrypt.hashSync('admin123', 10);
    api.prepare("INSERT INTO users (name, email, password_hash, role, status, credits) VALUES (?, ?, ?, ?, ?, ?)")
      .run('Admin', 'admin@admin.com', hash, 'admin', 'active', 999999);
    console.log('Default admin created: admin@admin.com / admin123');
  }
  seedDemoData();
  save();
}

const DEMO_SERVICES = [
  { name: 'Phone Unlock', description: 'Unlock any phone network', cost: 5, fields: [{label:'IMEI Number',type:'text',req:true},{label:'Phone Model',type:'text',req:true},{label:'Current Network',type:'text',req:true},{label:'Photo of Phone',type:'file',req:false}] },
  { name: 'FRP Bypass', description: 'Factory Reset Protection removal', cost: 8, fields: [{label:'IMEI Number',type:'text',req:true},{label:'Brand & Model',type:'text',req:true},{label:'Android Version',type:'text',req:true},{label:'Gmail/Account Email',type:'text',req:false}] },
  { name: 'Network Unlock', description: 'SIM unlock for all carriers', cost: 10, fields: [{label:'IMEI Number',type:'text',req:true},{label:'Phone Model',type:'text',req:true},{label:'Current Carrier',type:'text',req:true},{label:'Country',type:'text',req:true}] },
  { name: 'IMEI Repair', description: 'IMEI number repair service', cost: 15, fields: [{label:'Current IMEI',type:'text',req:true},{label:'Desired IMEI',type:'text',req:true},{label:'Phone Model',type:'text',req:true},{label:'Chipset/CPU',type:'text',req:false},{label:'Board Photo',type:'file',req:false}] },
  { name: 'Screen Repair', description: 'LCD/Touch screen replacement', cost: 12, fields: [{label:'Phone Model',type:'text',req:true},{label:'Issue Description',type:'textarea',req:true},{label:'Damaged Screen Photo',type:'file',req:true},{label:'Parts Needed',type:'text',req:false}] }
];

function seedDemoData() {
  const demoUser = api.prepare("SELECT id FROM users WHERE email = 'demo@demo.com'").get();
  if (!demoUser) {
    const hash = bcrypt.hashSync('demo123', 10);
    api.prepare("INSERT INTO users (name, email, password_hash, role, status, credits) VALUES (?, ?, ?, ?, ?, ?)")
      .run('Demo User', 'demo@demo.com', hash, 'client', 'active', 100);
    console.log('Demo user created: demo@demo.com / demo123 (100 credits)');
  }
  // Check if demo services already exist — if not, create all 5
  const existingPhoneUnlock = api.prepare("SELECT id FROM services WHERE name = 'Phone Unlock'").get();
  if (!existingPhoneUnlock) {
    DEMO_SERVICES.forEach(s => {
      const r = api.prepare("INSERT INTO services (name, description, active, cost) VALUES (?, ?, 1, ?)").run(s.name, s.description, s.cost);
      const svcId = r.lastInsertRowid;
      s.fields.forEach((f, i) => {
        api.prepare("INSERT INTO service_fields (service_id, label, field_type, required, sort_order) VALUES (?, ?, ?, ?, ?)")
          .run(svcId, f.label, f.type, f.req ? 1 : 0, i);
      });
    });
    console.log('5 demo services created with fields');
  }
}

// Wait for init before allowing use
const initPromise = init().catch(e => { console.error('DB init failed:', e); throw e; });

// Override prepare/exec to wait for init
const origPrepare = api.prepare;
const origExec = api.exec;

api.prepare = function(sql) {
  if (!db) throw new Error('Database not initialized yet');
  return origPrepare(sql);
};
api.exec = function(sql) {
  if (!db) throw new Error('Database not initialized yet');
  origExec(sql);
};

module.exports = api;
module.exports.initPromise = initPromise;
module.exports.DEMO_SERVICES = DEMO_SERVICES;
module.exports.seedDemoData = seedDemoData;

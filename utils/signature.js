const crypto = require('crypto');

class SignatureGenerator {
  constructor() {
    this.apiBaseUrl = 'https://service.carlcare.com';
  }

  generateTimeStamp() {
    return Date.now().toString();
  }

  generateSign(imei, timeStamp) {
    if (!imei || !timeStamp) return '';
    let padded = timeStamp;
    while (padded.length < imei.length) {
      padded += '0';
    }
    if (padded.length > imei.length) {
      padded = padded.substring(0, imei.length);
    }
    let result = '';
    for (let i = 0; i < imei.length; i++) {
      result += imei[i] + padded[i];
    }
    return result;
  }

  static decodeImeiFromSign(sign) {
    let imei = '';
    for (let i = 0; i < sign.length; i += 2) {
      imei += sign[i];
    }
    return imei;
  }

  generateLoginSign(secretKey = process.env.CARLCARE_SIGN_SECRET || 'carlcare_default_secret_key_2024') {
    const payload = `select-aicc-login${secretKey}`;
    return crypto.createHash('md5').update(payload).digest('hex');
  }

  buildImeiInfoUrl(imei) {
    const timeStamp = this.generateTimeStamp();
    const sign = this.generateSign(imei, timeStamp);
    return `${this.apiBaseUrl}/CarlcareClient/unlock-phone/imei-info?sign=${sign}&timeStamp=${timeStamp}`;
  }

  getHeaders(authToken) {
    return {
      'accept': 'application/json, text/plain, */*',
      'accept-language': 'en-US,en;q=0.9',
      'authorization': `Bearer ${authToken}`,
      'origin': 'https://www.carlcare.com',
      'referer': 'https://www.carlcare.com/',
      'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    };
  }
}

function extractDeviceDetails(responseData) {
  const data = responseData.data?.activeMessage;
  if (!data) return null;
  return {
    model: data.marketName || data.model || 'Unknown',
    status: data.status === 3 ? 'Active' : data.status === 2 ? 'Inactive' : 'Unknown',
    warranty: data.warrantyDuration || 'N/A',
    brand: data.brand || 'Unknown',
    imei: data.imei?.[0] || 'N/A',
    activeTime: data.activeTime || 'N/A',
    country: data.country || 'N/A'
  };
}

const RCSM_AES_KEY = 'a3tr@k30*!sjidgl@i34vnx12lks23)a';
const RCSM_AES_IV = 't6$#@k23_94sdsei';
const RCSM_BASE = 'https://rcsm-sg.realmeservice.com';

function encryptRcsmImei(imei) {
  const key = Buffer.from(RCSM_AES_KEY, 'utf8');
  const iv = Buffer.from(RCSM_AES_IV, 'utf8');
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let enc = cipher.update(imei, 'utf8', 'base64');
  enc += cipher.final('base64');
  return enc;
}

function buildRcsmUrl(encryptedImei) {
  return `${RCSM_BASE}/api/interface/mesinfo?ull&imei=${encodeURIComponent(encryptedImei)}&pcb=&batterysn=&adaptorsn=&chipsn=&guid=&color_box_sn=`;
}

function parseRcsmResponse(data) {
  if (!data || !data.Data || !data.Data.length) return null;
  const d = data.Data[0];
  return {
    model: d.MarketModel || d.Model || 'Unknown',
    brand: 'Realme',
    status: 'Active',
    warranty: 'N/A',
    imei: 'N/A',
    activeTime: d.ManufacturingDate || 'N/A',
    country: d.sales_org_name_l5 || 'N/A',
    color: d.Color || 'N/A',
    ram: d.Ram || 'N/A',
    rom: d.Rom || 'N/A',
    serialNumber: d.MobilePhoneSN || 'N/A',
    pcbNumber: d.Pcb || 'N/A',
    batterySN: d.BatterySN || 'N/A',
    adaptorSN: d.AdaptorSN || 'N/A',
    chipSN: d.ChipSN || 'N/A',
    softwareVersion: d.SoftwareVersion || 'N/A',
    productVersion: d.ProductVersion || 'N/A',
    material: d.Material || 'N/A',
    modelCode: d.Model || 'N/A'
  };
}

function loadRcsmToken() {
  const fs = require('fs');
  const path = require('path');
  const tokenFile = path.join(__dirname, '..', 'data', 'rcsm-token.json');
  try {
    if (fs.existsSync(tokenFile)) {
      return JSON.parse(fs.readFileSync(tokenFile, 'utf8'));
    }
  } catch (e) {}
  return null;
}

function saveRcsmToken(data) {
  const fs = require('fs');
  const path = require('path');
  const tokenFile = path.join(__dirname, '..', 'data', 'rcsm-token.json');
  const dir = path.dirname(tokenFile);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(tokenFile, JSON.stringify(data, null, 2));
}

function isRcsmTokenValid() {
  const t = loadRcsmToken();
  if (!t || !t.accessToken) return false;
  return Date.now() < (t.expiresAt || 0);
}

module.exports = { SignatureGenerator, extractDeviceDetails, encryptRcsmImei, buildRcsmUrl, parseRcsmResponse, loadRcsmToken, saveRcsmToken, isRcsmTokenValid, RCSM_BASE };

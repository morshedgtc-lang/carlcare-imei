# Carlcare IMEI Lookup Proxy - Integration Guide

## Project Structure
```
carlcare-imei-proxy/
├── app.js                 # Express entry point
├── package.json           # Dependencies
├── .env                   # Environment variables (create from .env.example)
├── routes/
│   └── imei.js           # POST /api/check-imei endpoint
└── utils/
    └── signature.js      # Signature generation logic
```

## Environment Variables (.env)
```env
PORT=3000
FRONTEND_URL=http://localhost:3000
CARLCARE_SIGN_SECRET=your_32_char_secret_key_here
```

## Installation
```bash
npm install
npm run dev   # Development with auto-reload
npm start     # Production
```

## API Endpoint

### POST /api/check-imei

**Request Body:**
```json
{
  "imei": "350286754549906",
  "authToken": "eyJhbGciOiJSUzI1NiJ9..."
}
```

**Response (Success):**
```json
{
  "success": true,
  "data": {
    "model": "SMART 9",
    "status": "Active",
    "warranty": "26-01-2027",
    "brand": "Infinix",
    "imei": "350286754549906",
    "activeTime": "2026-01-26 00:00:00",
    "country": "Nigeria"
  }
}
```

**Response (Error):**
```json
{
  "success": false,
  "error": "Invalid IMEI. Must be 15 digits."
}
```

## Frontend Integration Example

```javascript
async function checkImei(imei, authToken) {
  const response = await fetch('/api/check-imei', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ imei, authToken })
  });
  return response.json();
}

// Usage
const result = await checkImei('350286754549906', userAuthToken);
if (result.success) {
  console.log(result.data.model, result.data.status, result.data.warranty);
}
```

## Signature Generation Logic

The `SignatureGenerator` class in `utils/signature.js` handles:
- **timeStamp**: 13-digit milliseconds since epoch
- **sign**: 30-digit numeric hash from `SHA256(imei + timeStamp + secretKey)`

**Configuration:** Set `CARLCARE_SIGN_SECRET` in `.env` to match Carlcare's signing key.

## Security Notes
- Never commit `.env` or expose `CARLCARE_SIGN_SECRET`
- Rate limited to 100 requests per 15 minutes per IP
- Helmet.js for security headers
- Input validation on IMEI format (15 digits)
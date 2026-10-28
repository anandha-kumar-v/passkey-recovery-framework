const express = require('express');
const db = require('../db');
const { issueOTP, checkOTP } = require('../otp');

const router = express.Router();
const wrap = fn => (req, res) => fn(req, res).catch(e => {
  console.error(e);
  res.status(400).json({ error: e.message || 'Request failed' });
});

// Proxy to Pinata so API credentials never reach the browser.
// Allowed only for a verified user who has not stored CIDs yet (i.e. during signup).
router.post('/upload-fragment', wrap(async (req, res) => {
  const { userId, index, fragment } = req.body;
  if (typeof fragment !== 'string' || fragment.length > 200000) throw new Error('Invalid fragment');
  if (!Number.isInteger(index) || index < 1 || index > 6) throw new Error('Invalid index');
  const [u] = await db.query('SELECT email_verified FROM users WHERE id=?', [userId]);
  if (!u[0] || !u[0].email_verified) throw new Error('Not allowed');
  const [c] = await db.query('SELECT COUNT(*) n FROM fragment_cids WHERE user_id=?', [userId]);
  if (c[0].n > 0) throw new Error('Fragments already stored');

  const headers = { 'Content-Type': 'application/json' };
  if (process.env.PINATA_JWT) headers.Authorization = `Bearer ${process.env.PINATA_JWT}`;
  else {
    headers.pinata_api_key = process.env.PINATA_API_KEY;
    headers.pinata_secret_api_key = process.env.PINATA_SECRET_API_KEY;
  }
  const r = await fetch('https://api.pinata.cloud/pinning/pinJSONToIPFS', {
    method: 'POST', headers,
    body: JSON.stringify({
      pinataContent: { fragment, index, userId },
      pinataMetadata: { name: `prf-${userId}-frag${index}` },
    }),
  });
  // const data = await r.json();
  // if (!data.IpfsHash) throw new Error('IPFS upload failed');
  const data = await r.json();

if (!r.ok || !data.IpfsHash) {
  console.error('Pinata upload failed:', {
    status: r.status,
    response: data
  });

  throw new Error(
    `IPFS upload failed (HTTP ${r.status}): ${
      data.error || data.message || JSON.stringify(data)
    }`
  );
}
  res.json({ cid: data.IpfsHash });
}));

// Store AES-encrypted CIDs (5 shares + 1 parity)
router.post('/store-cids', wrap(async (req, res) => {
  const { userId, encryptedCIDs } = req.body;
  if (!Array.isArray(encryptedCIDs) || encryptedCIDs.length < 5 || encryptedCIDs.length > 6)
    throw new Error('Invalid CID list');
  const [u] = await db.query('SELECT email_verified FROM users WHERE id=?', [userId]);
  if (!u[0] || !u[0].email_verified) throw new Error('Not allowed');
  const [c] = await db.query('SELECT COUNT(*) n FROM fragment_cids WHERE user_id=?', [userId]);
  if (c[0].n > 0) throw new Error('CIDs already stored');
  for (let i = 0; i < encryptedCIDs.length; i++)
    await db.query('INSERT INTO fragment_cids (user_id, idx, encrypted_cid) VALUES (?,?,?)',
      [userId, i + 1, String(encryptedCIDs[i])]);
  res.json({ ok: true });
}));

// Recovery step 1: email OTP
router.post('/request-recovery', wrap(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const [rows] = await db.query('SELECT id FROM users WHERE email=? AND unique_id=? AND public_key IS NOT NULL',
    [email, req.body.uniqueId]);
  if (!rows[0]) throw new Error('Account not found');
  await issueOTP(rows[0].id, email, 'recovery');
  res.json({ userId: rows[0].id });
}));

// Recovery step 2: OTP verified -> salts + encrypted CIDs (useless without the password)
router.post('/get-encrypted-cids', wrap(async (req, res) => {
  const { userId, otp } = req.body;
  await checkOTP(userId, otp);
  const [u] = await db.query('SELECT salt1, salt2 FROM users WHERE id=?', [userId]);
  const [c] = await db.query('SELECT encrypted_cid FROM fragment_cids WHERE user_id=? ORDER BY idx', [userId]);
  if (!u[0] || !c.length) throw new Error('No recovery data found');
  res.json({ salt1: u[0].salt1, salt2: u[0].salt2, encryptedCIDs: c.map(r => r.encrypted_cid) });
}));

module.exports = router;

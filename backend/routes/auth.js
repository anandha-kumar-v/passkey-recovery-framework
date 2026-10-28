const express = require('express');
const crypto = require('crypto');
const { v4: uuid } = require('uuid');
const db = require('../db');
const { issueOTP, checkOTP } = require('../otp');

const router = express.Router();
const wrap = fn => (req, res) => fn(req, res).catch(e => {
  console.error(e);
  res.status(400).json({ error: e.message || 'Request failed' });
});

// 1. Start signup: create/refresh unverified user and email an OTP
router.post('/signup/init', wrap(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  if (!/^\S+@\S+\.\S+$/.test(email)) throw new Error('Invalid email');
  const [rows] = await db.query('SELECT id, public_key FROM users WHERE email=?', [email]);
  if (rows[0] && rows[0].public_key) throw new Error('Email already registered');
  const userId = rows[0] ? rows[0].id : uuid();
  if (!rows[0]) await db.query('INSERT INTO users (id, email) VALUES (?,?)', [userId, email]);
  await issueOTP(userId, email, 'signup');
  res.json({ userId });
}));

// 2. Verify email OTP
router.post('/signup/verify-otp', wrap(async (req, res) => {
  const { userId, otp } = req.body;
  await checkOTP(userId, otp);
  await db.query('UPDATE users SET email_verified=1 WHERE id=?', [userId]);
  res.json({ ok: true });
}));

// 3. Register public key + unique ID, hand back the two PBKDF2 salts
router.post('/signup/complete', wrap(async (req, res) => {
  const { userId, uniqueId, publicKey } = req.body;
  if (!uniqueId || !/^-----BEGIN PUBLIC KEY-----/.test(publicKey || '')) throw new Error('Invalid registration data');
  const [rows] = await db.query('SELECT email_verified, public_key FROM users WHERE id=?', [userId]);
  if (!rows[0] || !rows[0].email_verified) throw new Error('Email not verified');
  if (rows[0].public_key) throw new Error('Already registered');
  const [dup] = await db.query('SELECT id FROM users WHERE unique_id=?', [uniqueId]);
  if (dup[0]) throw new Error('User ID already taken');
  const salt1 = crypto.randomBytes(16).toString('hex');
  const salt2 = crypto.randomBytes(16).toString('hex');
  await db.query('UPDATE users SET unique_id=?, public_key=?, salt1=?, salt2=? WHERE id=?',
    [uniqueId, publicKey, salt1, salt2, userId]);
  res.json({ salt1, salt2 });
}));

// Login: server encrypts a random challenge to the user's public key
router.post('/login/init', wrap(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const [rows] = await db.query('SELECT id, public_key FROM users WHERE email=? AND unique_id=?',
    [email, req.body.uniqueId]);
  const u = rows[0];
  if (!u || !u.public_key) throw new Error('Account not found');
  const challenge = crypto.randomBytes(32).toString('hex');
  const cipher = crypto.publicEncrypt(
    { key: u.public_key, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    Buffer.from(challenge)
  ).toString('base64');
  const hash = crypto.createHash('sha256').update(challenge).digest('hex');
  await db.query('UPDATE login_challenges SET used=1 WHERE user_id=? AND used=0', [u.id]);
  await db.query(
    `INSERT INTO login_challenges (user_id, challenge_cipher, challenge_hash, expires_at)
     VALUES (?,?,?,DATE_ADD(NOW(), INTERVAL 5 MINUTE))`, [u.id, cipher, hash]);
  res.json({ userId: u.id, challengeCipher: cipher });
}));

// Login: client returns the decrypted challenge
router.post('/login/verify', wrap(async (req, res) => {
  const { userId, decryptedChallenge } = req.body;
  const [rows] = await db.query(
    `SELECT id, challenge_hash FROM login_challenges
     WHERE user_id=? AND used=0 AND expires_at > NOW() ORDER BY id DESC LIMIT 1`, [userId]);
  if (!rows[0]) throw new Error('Challenge expired or not found');
  await db.query('UPDATE login_challenges SET used=1 WHERE id=?', [rows[0].id]);  // single use
  const got = crypto.createHash('sha256').update(String(decryptedChallenge || '')).digest();
  const want = Buffer.from(rows[0].challenge_hash, 'hex');
  if (!crypto.timingSafeEqual(got, want)) throw new Error('Authentication failed');
  res.json({ ok: true });
}));

module.exports = router;

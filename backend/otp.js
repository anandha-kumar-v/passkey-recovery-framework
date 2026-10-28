const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const db = require('./db');

const OTP_TTL_MIN = 10;
const MAX_ATTEMPTS = 5;

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_APP_PASSWORD },
});

async function issueOTP(userId, email, purpose) {
  const otp = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  const hash = await bcrypt.hash(otp, 10);
  await db.query(
    `UPDATE users SET otp_hash=?, otp_expires=DATE_ADD(NOW(), INTERVAL ? MINUTE), otp_attempts=0 WHERE id=?`,
    [hash, OTP_TTL_MIN, userId]
  );
  await transporter.sendMail({
    from: `"Passkey Recovery" <${process.env.GMAIL_USER}>`,
    to: email,
    subject: `Your ${purpose} code`,
    text: `Your one-time code is ${otp}. It expires in ${OTP_TTL_MIN} minutes.`,
  });
}

// Returns true if OTP is valid; consumes it. Throws a user-facing Error otherwise.
async function checkOTP(userId, otp) {
  const [rows] = await db.query(
    `SELECT otp_hash, otp_attempts, otp_expires > NOW() AS live FROM users WHERE id=?`, [userId]);
  const u = rows[0];
  if (!u || !u.otp_hash) throw new Error('No OTP requested');
  if (u.otp_attempts >= MAX_ATTEMPTS) throw new Error('Too many attempts. Request a new OTP');
  if (!u.live) throw new Error('OTP expired');
  const ok = await bcrypt.compare(String(otp), u.otp_hash);
  if (!ok) {
    await db.query('UPDATE users SET otp_attempts=otp_attempts+1 WHERE id=?', [userId]);
    throw new Error('Invalid OTP');
  }
  await db.query('UPDATE users SET otp_hash=NULL, otp_expires=NULL, otp_attempts=0 WHERE id=?', [userId]);
  return true;
}

module.exports = { issueOTP, checkOTP };

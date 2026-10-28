CREATE DATABASE IF NOT EXISTS passkey_recovery;
USE passkey_recovery;

CREATE TABLE IF NOT EXISTS users (
  id VARCHAR(36) PRIMARY KEY,
  email VARCHAR(255) NOT NULL UNIQUE,
  unique_id VARCHAR(64) UNIQUE,
  public_key TEXT,
  salt1 CHAR(32),
  salt2 CHAR(32),
  email_verified TINYINT(1) DEFAULT 0,
  otp_hash VARCHAR(100),
  otp_expires DATETIME,
  otp_attempts INT DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS fragment_cids (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id VARCHAR(36) NOT NULL,
  idx TINYINT NOT NULL,
  encrypted_cid TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_user_idx (user_id, idx),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Stores a SHA-256 hash of the challenge, not the plaintext.
CREATE TABLE IF NOT EXISTS login_challenges (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id VARCHAR(36) NOT NULL,
  challenge_cipher TEXT NOT NULL,
  challenge_hash CHAR(64) NOT NULL,
  expires_at DATETIME NOT NULL,
  used TINYINT(1) DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

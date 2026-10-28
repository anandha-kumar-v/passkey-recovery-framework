# Fault-Tolerant Decentralized Passkey Recovery Framework

A zero-knowledge passkey system that generates and stores a private key only on the user's device, then lets the user recover it from encrypted fragments stored on IPFS, without the server ever seeing the key or the password.

> B.E. Cyber Security final-year project, Paavai Engineering College, Namakkal (Anna University), April 2026.

## Why this project

Most authentication systems keep credentials or keys on a central server. That creates a single point of failure, exposes users to credential theft, and often makes a lost private key unrecoverable. This framework removes the server from the trust model:

- The private key is generated in the browser and never leaves it.
- Login uses an RSA challenge-response, so no password is ever transmitted.
- Recovery rebuilds the key from fragments spread across IPFS, tolerating missing or corrupted pieces.

## Features

- **Client-side key generation** with the WebCrypto API (RSA-OAEP, 2048-bit, SHA-256).
- **Non-extractable key storage** in IndexedDB, so scripts can use the key but cannot read it out.
- **Shamir's Secret Sharing** over GF(256), 5 shares with a threshold of 3, implemented in plain JavaScript using a cryptographically secure random source.
- **XOR parity share** as a 6th fragment, used to detect a corrupted fragment.
- **Fault-tolerant recovery:** tampered or missing fragments are skipped (AES-GCM authentication fails on them), and share combinations are tried until a valid private key is produced.
- **AES-256-GCM encryption** of every fragment, with keys derived by PBKDF2 (310,000 iterations, SHA-512).
- **Two independent derived keys:** one encrypts fragments, the other encrypts their IPFS CIDs before they are stored in MySQL.
- **Passwordless login:** the server encrypts a random challenge to the user's public key, the browser decrypts it, and the server checks the answer. Challenges are single-use, expire after 5 minutes, and only a SHA-256 hash is stored.
- **Email OTP** for signup and recovery (bcrypt-hashed, 10-minute expiry, 5 attempts maximum).
- **Rate limiting** on all API routes.

## How it works

**Signup**
1. The user verifies their email with an OTP.
2. The browser generates an RSA key pair. The public key goes to the server, and the private key is stored in IndexedDB as a non-extractable key.
3. The private key is split into 5 Shamir shares plus 1 XOR parity share.
4. Each fragment is encrypted with AES-256-GCM (Key 1) and pinned to IPFS through the backend, which holds the Pinata credentials.
5. The 6 CIDs are encrypted with Key 2 and stored in MySQL.

**Login**
1. The server encrypts a random challenge with the user's public key.
2. The browser decrypts it with the private key and sends it back.
3. The server compares hashes and grants access.

**Recovery**
1. The user verifies their email with an OTP and enters their password.
2. The browser re-derives Key 1 and Key 2 with PBKDF2, using the salts returned by the server.
3. It decrypts the CIDs, fetches the fragments from IPFS, and decrypts them.
4. Valid shares are combined to rebuild the private key, which is stored back on the device.

**What the server stores:** public keys, salts, OTP hashes, encrypted CIDs, and challenge hashes. It never receives the private key, the password, or any derived key.

## Tech stack

| Layer | Technology |
|---|---|
| Frontend | HTML, CSS, JavaScript (single page), WebCrypto API, IndexedDB |
| Backend | Node.js 18+, Express |
| Database | MySQL |
| Decentralized storage | IPFS via Pinata |
| Email | Nodemailer with Gmail SMTP |
| Security libraries | bcryptjs, express-rate-limit |

## Project structure

```
passkey/
├── backend/
│   ├── server.js            # Express app and route mounting
│   ├── db.js                # MySQL connection pool
│   ├── otp.js               # OTP issue/verify and email sending
│   ├── schema.sql           # Database schema
│   ├── routes/
│   │   ├── auth.js          # Signup and challenge-response login
│   │   └── recovery.js      # IPFS upload proxy, CID storage, recovery
│   ├── package.json
│   └── .env.example         # Copy to .env and fill in
├── frontend/public/
│   └── index.html           # Complete client application
├── .gitignore
└── README.md
```

## Getting started

### Prerequisites

- Node.js 18 or newer
- MySQL 8 (or MariaDB)
- Chrome or Firefox
- A Gmail account with 2-Step Verification and an [app password](https://myaccount.google.com/apppasswords)
- A [Pinata](https://pinata.cloud) account and an API JWT with pinning permission

### Installation

```bash
git clone https://github.com/<your-username>/<your-repo>.git
cd <your-repo>/backend
npm install
```

Create the database tables:

```bash
mysql -u root -p < schema.sql
```

Create your environment file:

```bash
cp .env.example .env      # on Windows: copy .env.example .env
```

Fill in `.env`:

```
PORT=5000
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your-mysql-password
DB_NAME=passkey_recovery
GMAIL_USER=you@gmail.com
GMAIL_APP_PASSWORD=your-16-character-app-password
PINATA_JWT=your-pinata-jwt
```

Start the server:

```bash
npm start
```

Open **http://localhost:5000**. Use `localhost` and not a LAN IP, because WebCrypto and IndexedDB require a secure context.

### Using the app

1. **Sign Up:** enter your email, verify the OTP, choose a User ID and password. You will see 5 fragment cards and 1 parity card.
2. **Login:** use the same email and User ID, in the same browser where you signed up.
3. **Recover:** request an OTP, then enter it with your original password to restore the key on the current browser.

## API reference

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/auth/signup/init` | Start signup and send OTP |
| POST | `/api/auth/signup/verify-otp` | Verify the signup OTP |
| POST | `/api/auth/signup/complete` | Register public key, return PBKDF2 salts |
| POST | `/api/auth/login/init` | Return an encrypted challenge |
| POST | `/api/auth/login/verify` | Verify the decrypted challenge |
| POST | `/api/passkey/upload-fragment` | Pin an encrypted fragment to IPFS |
| POST | `/api/passkey/store-cids` | Store the encrypted CIDs |
| POST | `/api/recovery/request-recovery` | Send a recovery OTP |
| POST | `/api/recovery/get-encrypted-cids` | Verify the OTP, return salts and encrypted CIDs |
| GET | `/api/health` | Health check |

## Testing fault tolerance

After a successful signup, damage the stored data and run recovery again:

- Unpin or delete one or two fragments in the Pinata dashboard, then recover. The key is still rebuilt from the remaining valid fragments.
- Recover with a wrong password. Decryption fails at the AES-GCM step, as expected.
- With fewer than 3 valid fragments, recovery fails with a clear error instead of returning a wrong key.

## Security notes and limitations

- **The password is the recovery secret.** If it is forgotten, recovery is not possible, by design. The server cannot reset it because it never knows it.
- **Fragments are on a public IPFS gateway.** They are AES-256-GCM encrypted, so they are useless without the password-derived key, but their ciphertext is publicly retrievable by anyone who learns a CID.
- **A strong password matters.** An attacker who obtains the encrypted CIDs, the salts, and the fragments can try offline password guesses, and PBKDF2 only slows that down.
- **The key lives on one device.** Multi-device sync is not implemented; use the recovery flow on a second device.
- **Never commit `.env`.** It contains your database, Gmail and Pinata credentials.
- This is an academic prototype and has not had an independent security audit.

## Future work

- WebAuthn / FIDO2 hardware key integration
- Multi-device synchronization
- Zero-knowledge proof based password verification
- Blockchain anchoring of CID hashes for tamper evidence
- Automatic fragment health monitoring and re-pinning

## Team

| Name | Register No. |
|---|---|
| Anandha Kumar V | 622122111008 |
| Chandru K | 622122111026 |
| Chennakesavan M | 622122111028 |
| Hariharan R S | 622122111049 |

**Supervisor:** Dr. S. Sasikala, M.E., Ph.D., Associate Professor, Department of Cyber Security
**Institution:** Paavai Engineering College (Autonomous), Namakkal, affiliated to Anna University, Chennai

## License

This project is licensed under the MIT License. See the LICENSE file.
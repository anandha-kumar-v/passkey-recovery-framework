require('dotenv').config();
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, '../frontend/public')));

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 60 });
app.use('/api/', limiter);

app.use('/api/auth', require('./routes/auth'));
app.use('/api/passkey', require('./routes/recovery'));
app.use('/api/recovery', require('./routes/recovery'));

app.get('/api/health', (_, res) => res.json({ ok: true }));

// Serve frontend
app.get('*', (_, res) =>
  res.sendFile(path.join(__dirname, '../frontend/public/index.html'))
);

app.listen(PORT, () =>
  console.log(`\n  Passkey Recovery v2 → http://localhost:${PORT}\n`)
);

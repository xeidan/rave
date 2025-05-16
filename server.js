require('dotenv').config();
const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const { body, validationResult } = require('express-validator');
const { Pool } = require('pg');
const { parse } = require('pg-connection-string');
const nodemailer = require('nodemailer');

// Middleware
app.use(cors({ origin: '*' }));
app.use(express.json());
app.use(morgan('combined'));

// Rate Limiter
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
}));

// DB connection
let pool;
if (process.env.DATABASE_URL) {
  const config = parse(process.env.DATABASE_URL);
  config.ssl = { rejectUnauthorized: false };
  pool = new Pool(config);
} else {
  pool = new Pool({
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    database: process.env.DB_DATABASE,
  });
}

// Email setup
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

async function sendConfirmationEmail(email, name) {
  try {
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Welcome to Rave!',
      html: `<p>Hi ${name},</p><p>Thank you for joining the Rave waitlist!</p>`,
    });
  } catch (err) {
    console.error('Email error:', err);
  }
}

function generateReferralCode() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  return Array.from({ length: 8 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
}

function generateToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });
}

function verifyToken(token) {
  try {
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    return null;
  }
}

function authenticateAdmin(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.sendStatus(401);
  const user = verifyToken(token);
  if (!user) return res.sendStatus(403);
  req.user = user;
  next();
}

// Admin login
app.post('/admin/login', async (req, res) => {
  const { username, password } = req.body;
  const client = await pool.connect();
  try {
    const result = await client.query('SELECT * FROM admin_users WHERE username = $1', [username]);
    if (result.rows.length && await bcrypt.compare(password, result.rows[0].password)) {
      return res.json({ token: generateToken({ username }) });
    }
    res.status(401).json({ error: 'Invalid credentials' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  } finally {
    client.release();
  }
});

// ✅ JOIN USER ENDPOINT
app.post('/users', [
  body('first_name').notEmpty().withMessage('First name is required'),
  body('last_name').notEmpty().withMessage('Last name is required'),
  body('email').isEmail().withMessage('Invalid email address'),
  body('referred_by').optional({ nullable: true, checkFalsy: true }).isAlphanumeric().withMessage('Referral code must be alphanumeric')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { first_name, last_name, email, phone, password, referred_by } = req.body;
  const name = `${first_name} ${last_name}`;
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    if (referred_by) {
      const ref = await client.query('SELECT * FROM users WHERE referral_code = $1', [referred_by]);
      if (ref.rows.length) {
        await client.query('UPDATE users SET rave_coins = rave_coins + 10 WHERE referral_code = $1', [referred_by]);
      }
    }

    const referralCode = generateReferralCode();
    const result = await client.query(
      `INSERT INTO users (first_name, last_name, email, phone, password, referral_code, referred_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
      [first_name, last_name, email, phone, password, referralCode, referred_by || null]
    );

    const position = parseInt((await client.query(
      'SELECT COUNT(*) FROM users WHERE id <= $1', [result.rows[0].id]
    )).rows[0].count, 10);

    await client.query('UPDATE users SET position = $1 WHERE id = $2', [position, result.rows[0].id]);
    await client.query('COMMIT');

    await sendConfirmationEmail(email, name);

    res.status(201).json({
      message: 'User signed up successfully',
      referral_code: referralCode,
      position
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Internal server error' });
  } finally {
    client.release();
  }
});

// Admin dashboard
app.get('/admin/dashboard', authenticateAdmin, async (req, res) => {
  try {
    const [totalUsers, totalCoins, topReferrers] = await Promise.all([
      pool.query('SELECT COUNT(*) FROM users'),
      pool.query('SELECT SUM(rave_coins) FROM users'),
      pool.query(`SELECT referred_by, COUNT(*) AS count 
                  FROM users 
                  WHERE referred_by IS NOT NULL 
                  GROUP BY referred_by 
                  ORDER BY count DESC LIMIT 5`)
    ]);
    res.json({
      total_users: parseInt(totalUsers.rows[0].count, 10),
      total_rave_coins: parseInt(totalCoins.rows[0].sum || 0, 10),
      top_referrers: topReferrers.rows
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Health check
app.get('/', (req, res) => {
  res.send('Rave Waitlist API Running');
});

const PORT = process.env.PORT || 5001;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

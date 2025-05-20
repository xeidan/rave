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
app.set('trust proxy', 1); // Fixes rate-limit trust issue on Heroku

// Rate Limiter
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));

// Database Connection
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

// Email Setup
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

// Admin Login
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

// User Sign-up
app.post('/users', [
  body('first_name').notEmpty(),
  body('last_name').notEmpty(),
  body('email').isEmail(),
  body('password').notEmpty(),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { first_name, last_name, email, phone, password, referred_by } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const existing = await client.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Email already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    console.log('🔐 HASHED PASSWORD:', hashedPassword);

    const referralCode = generateReferralCode();

    if (referred_by) {
        const refUserRes = await client.query(
          'SELECT id, email, first_name, bonus_awarded FROM users WHERE referral_code = $1',
          [referred_by]
        );
      
        if (refUserRes.rows.length > 0) {
          const refUserId = refUserRes.rows[0].id;
      
          // Always give 10 coins for any referral
          await client.query('UPDATE users SET rave_coins = rave_coins + 10 WHERE id = $1', [refUserId]);
      
          // Count how many users used this code
          const referralCountRes = await client.query(
            'SELECT COUNT(*) FROM users WHERE referred_by = $1',
            [referred_by]
          );
          const referralCount = parseInt(referralCountRes.rows[0].count, 10);
      
          // Award bonus if exactly 5 referrals and not yet awarded
          if (referralCount >= 5 && !refUserRes.rows[0].bonus_awarded) {
            await client.query(`
              UPDATE users 
              SET rave_coins = rave_coins + 100, bonus_awarded = TRUE 
              WHERE id = $1
            `, [refUserId]);
      
            // Send email
            const refUserEmail = refUserRes.rows[0].email;
            const refUserName = refUserRes.rows[0].first_name;
      
            await transporter.sendMail({
              from: process.env.EMAIL_USER,
              to: refUserEmail,
              subject: '🎉 You just earned 100 bonus Rave Coins!',
              html: `
                <p>Hi ${refUserName},</p>
                <p>Congratulations! You've referred 5 friends and earned a <strong>100 Rave Coin bonus</strong>.</p>
                <p>You can redeem your coins for rewards after the waitlist phase ends.</p>
                <p>Keep going – every extra referral still earns you <strong>10 coins each</strong>!</p>
                <p>– Team Rave</p>
              `
            });
          }
        }
      }
      
      

    const result = await client.query(`
      INSERT INTO users (first_name, last_name, email, phone, password, referral_code, referred_by)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING id
    `, [first_name, last_name, email, phone, hashedPassword, referralCode, referred_by || null]);

    const positionRes = await client.query('SELECT COUNT(*) FROM users WHERE id <= $1', [result.rows[0].id]);
    const position = parseInt(positionRes.rows[0].count, 10);

    await client.query('UPDATE users SET position = $1 WHERE id = $2', [position, result.rows[0].id]);
    await client.query('COMMIT');

    res.status(201).json({ message: 'User created', referral_code: referralCode, position });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error creating user:', err.message);
    res.status(500).json({ error: 'Server error' });
  } finally {
    client.release();
  }
});

// User Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const client = await pool.connect();
  try {
    const result = await client.query('SELECT * FROM users WHERE LOWER(email) = LOWER($1)', [email]);
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'User not found' });
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: 'Incorrect password' });

    res.json({
      name: `${user.first_name} ${user.last_name}`,
      email: user.email,
      referral_code: user.referral_code,
      position: user.position,
      rave_coins: user.rave_coins
    });
  } catch (err) {
    console.error('Login Error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  } finally {
    client.release();
  }
});

// Get referrer info by referral code
app.get('/referrer/:code', async (req, res) => {
    const { code } = req.params;
    const client = await pool.connect();
    try {
      const result = await client.query(
        'SELECT first_name, last_name FROM users WHERE referral_code = $1',
        [code]
      );
      if (result.rows.length > 0) {
        const user = result.rows[0];
        return res.json({ name: `${user.first_name} ${user.last_name}` });
      } else {
        return res.status(404).json({ error: 'Referrer not found' });
      }
    } catch (err) {
      console.error('Error fetching referrer:', err.message);
      res.status(500).json({ error: 'Internal server error' });
    } finally {
      client.release();
    }
  });
  

// Admin Dashboard
app.get('/admin/dashboard', authenticateAdmin, async (req, res) => {
  try {
    const [totalUsers, totalCoins, topReferrers] = await Promise.all([
      pool.query('SELECT COUNT(*) FROM users'),
      pool.query('SELECT SUM(rave_coins) FROM users'),
      pool.query(`
        SELECT referred_by, COUNT(*) AS count 
        FROM users 
        WHERE referred_by IS NOT NULL 
        GROUP BY referred_by 
        ORDER BY count DESC LIMIT 5
      `)
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

// GET /me
app.get('/me', async (req, res) => {
    const { email } = req.query;
    if (!email) return res.status(400).json({ error: 'Email is required' });
  
    const client = await pool.connect();
    try {
      const result = await client.query(
        `SELECT first_name, last_name, email, referral_code, rave_coins, bonus_awarded,
                (SELECT COUNT(*) FROM users WHERE referred_by = u.referral_code) AS referral_count
           FROM users u WHERE email = $1`, [email]
      );
  
      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'User not found' });
      }
  
      const user = result.rows[0];
      res.json({
        name: `${user.first_name} ${user.last_name}`,
        email: user.email,
        referral_code: user.referral_code,
        rave_coins: user.rave_coins,
        referral_count: parseInt(user.referral_count, 10),
        bonus_awarded: user.bonus_awarded
      });
    } catch (err) {
      console.error('GET /me error:', err.message);
      res.status(500).json({ error: 'Server error' });
    } finally {
      client.release();
    }
  });
  
  

  // POST /reward/ad-view
app.post('/reward/ad-view', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required' });
  
    const client = await pool.connect();
    try {
      const userRes = await client.query('SELECT id, ad_views_today FROM users WHERE email = $1', [email]);
      if (!userRes.rows.length) return res.status(404).json({ error: 'User not found' });
  
      const user = userRes.rows[0];
      const views = user.ad_views_today || 0;
  
      if (views >= 3) return res.status(400).json({ error: 'Limit reached for today' });
  
      const updatedViews = views + 1;
      let coinsToAdd = 0;
      if (updatedViews === 3) coinsToAdd = 50;
  
      await client.query('BEGIN');
      await client.query(
        'UPDATE users SET ad_views_today = $1, rave_coins = rave_coins + $2 WHERE id = $3',
        [updatedViews, coinsToAdd, user.id]
      );
      await client.query('COMMIT');
  
      res.json({ message: 'Ad view tracked', earned: coinsToAdd > 0 });
    } catch (err) {
      await client.query('ROLLBACK');
      console.error('Ad reward error:', err);
      res.status(500).json({ error: 'Server error' });
    } finally {
      client.release();
    }
  });
  

  if (referralCount >= 5 && !refUserRes.rows[0].bonus_awarded) {
    await client.query('UPDATE users SET rave_coins = rave_coins + 100, bonus_awarded = TRUE WHERE id = $1', [refUserId]);
  
    // Email congratulation
    const refEmailRes = await client.query('SELECT email, first_name FROM users WHERE id = $1', [refUserId]);
    if (refEmailRes.rows.length > 0) {
      const { email: refEmail, first_name: refName } = refEmailRes.rows[0];
      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: refEmail,
        subject: '🎉 You earned a referral bonus!',
        html: `<p>Hi ${refName},</p><p>You've just earned 100 Rave Coins for referring 5 users! Keep sharing your link to earn more.</p>`
      });
    }
  }
  

  

  
  app.post('/reward/ad-view', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
  
    const client = await pool.connect();
    try {
      const userRes = await client.query('SELECT id, ad_views_today, last_ad_reset FROM users WHERE email = $1', [email]);
      if (!userRes.rows.length) return res.status(404).json({ error: 'User not found' });
  
      const user = userRes.rows[0];
      const today = new Date().toISOString().slice(0, 10);
  
      if (user.last_ad_reset?.toISOString().slice(0, 10) !== today) {
        await client.query('UPDATE users SET ad_views_today = 0, last_ad_reset = $1 WHERE email = $2', [today, email]);
        user.ad_views_today = 0;
      }
  
      const newCount = user.ad_views_today + 1;
  
      if (newCount < 3) {
        await client.query('UPDATE users SET ad_views_today = $1 WHERE email = $2', [newCount, email]);
        return res.json({ message: `Ad viewed. ${newCount}/3` });
      }
  
      // Grant coins and reset view counter
      await client.query('UPDATE users SET ad_views_today = 0, rave_coins = rave_coins + 50, last_ad_reset = $1 WHERE email = $2', [today, email]);
      res.json({ message: '✅ 50 Rave Coins earned for watching 3 ads!' });
    } catch (err) {
      console.error('Ad view reward error:', err);
      res.status(500).json({ error: 'Server error' });
    } finally {
      client.release();
    }
  });

  
  app.patch('/users/reset-ads', async (req, res) => {
  const today = new Date().toISOString().slice(0, 10);
  try {
    await pool.query(`UPDATE users SET ad_views_today = 0, last_ad_reset = $1`, [today]);
    res.json({ message: 'Ad views reset for all users.' });
  } catch (err) {
    console.error('Reset ads error:', err);
    res.status(500).json({ error: 'Failed to reset' });
  }
});

app.get('/health', (req, res) => {
    res.json({
      status: 'ok',
      routes: [
        'GET /',
        'POST /users',
        'POST /login',
        'GET /referrer/:code',
        'GET /me',
        'POST /reward/ad-view',
        'PATCH /users/reset-ads',
        'POST /admin/login',
        'GET /admin/dashboard'
      ]
    });
  });
  

// Health check
app.get('/', (req, res) => {
  res.send('Rave Waitlist API Running');
});

const PORT = process.env.PORT || 5001;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

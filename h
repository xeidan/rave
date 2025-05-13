require('dotenv').config();

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult, param } = require('express-validator');
const { Pool } = require('pg');
const { parse } = require('pg-connection-string');
const nodemailer = require('nodemailer');

const app = express();
app.use(express.json());

// Database Connection
let pool;
if (process.env.DATABASE_URL) {
    const pgconfig = parse(process.env.DATABASE_URL);
    pool = new Pool(pgconfig);
} else {
    pool = new Pool({
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        host: process.env.DB_HOST,
        port: process.env.DB_PORT,
        database: process.env.DB_DATABASE,
    });
}

// Nodemailer setup
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

async function sendConfirmationEmail(email, name) {
    try {
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Welcome to Rave!',
            html: `<p>Hi ${name},</p><p>Thank you for joining the Rave waitlist!</p><p>We'll keep you updated.</p>`
        };
        await transporter.sendMail(mailOptions);
        console.log(`Confirmation email sent to ${email}`);
    } catch (error) {
        console.error('Error sending email:', error);
    }
}

function generateReferralCode() {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let referralCode = '';
    for (let i = 0; i < 8; i++) {
        referralCode += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return referralCode;
}

async function hashPassword(password) {
    const saltRounds = 10;
    return bcrypt.hash(password, saltRounds);
}

function generateToken(payload) {
    return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });
}

function verifyToken(token) {
    try {
        return jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
        return null;
    }
}

function authenticateAdmin(req, res, next) {
    const authHeader = req.headers.authorization;
    if (authHeader) {
        const token = authHeader.split(' ')[1];
        const user = verifyToken(token);
        if (user) {
            req.user = user;
            next();
        } else {
            res.sendStatus(403);
        }
    } else {
        res.sendStatus(401);
    }
}

app.get('/', (req, res) => {
    res.send('Rave Waitlist API');
});

app.post('/users', [
    body('name').notEmpty().withMessage('Name is required'),
    body('email').isEmail().withMessage('Invalid email'),
    body('referred_by').optional().isAlphanumeric().withMessage('Referral code must be alphanumeric'),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, referred_by } = req.body;
    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        if (referred_by) {
            const referringUser = await client.query('SELECT * FROM users WHERE referral_code = $1', [referred_by]);
            if (referringUser.rows.length > 0) {
                await client.query('UPDATE users SET rave_coins = rave_coins + 10 WHERE referral_code = $1', [referred_by]);
            }
        }

        const referralCode = generateReferralCode();
        const result = await client.query(
            'INSERT INTO users (name, email, referral_code, referred_by) VALUES ($1, $2, $3, $4) RETURNING id',
            [name, email, referralCode, referred_by]
        );

        const positionResult = await client.query('SELECT COUNT(*) FROM users WHERE id <= $1', [result.rows[0].id]);
        const position = parseInt(positionResult.rows[0].count, 10);

        await client.query('UPDATE users SET position = $1 WHERE id = $2', [position, result.rows[0].id]);

        await client.query('COMMIT');
        sendConfirmationEmail(email, name);

        res.status(201).json({ message: 'User signed up successfully', referral_code: referralCode, position });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    } finally {
        client.release();
    }
});

app.post('/admin/login', async (req, res) => {
    const { username, password } = req.body;
    const client = await pool.connect();
    try {
        const result = await client.query('SELECT * FROM admin_users WHERE username = $1', [username]);
        if (result.rows.length > 0) {
            const user = result.rows[0];
            const passwordMatch = await bcrypt.compare(password, user.password);
            if (passwordMatch) {
                const token = generateToken({ username: user.username });
                res.json({ token });
            } else {
                res.status(401).json({ error: 'Invalid credentials' });
            }
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    } finally {
        client.release();
    }
});

app.get('/admin/users', authenticateAdmin, async (req, res) => {
    const client = await pool.connect();
    try {
        const result = await client.query('SELECT * FROM users');
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    } finally {
        client.release();
    }
});

app.put('/admin/users/:id/position', authenticateAdmin, [
    param('id').isInt(),
    body('position').isInt(),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { id } = req.params;
    const { position } = req.body;

    const client = await pool.connect();
    try {
        await client.query('UPDATE users SET position = $1 WHERE id = $2', [position, id]);
        res.sendStatus(204);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    } finally {
        client.release();
    }
});

app.delete('/admin/users/:id', authenticateAdmin, async (req, res) => {
    const { id } = req.params;
    const client = await pool.connect();
    try {
        await client.query('DELETE FROM users WHERE id = $1', [id]);
        res.sendStatus(204);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    } finally {
        client.release();
    }
});

app.get('/users/:referralCode', async (req, res) => {
    const { referralCode } = req.params;
    try {
        const result = await pool.query('SELECT position, referral_code, rave_coins FROM users WHERE referral_code = $1', [referralCode]);
        if (result.rows.length > 0) {
            res.json(result.rows[0]);
        } else {
            res.status(404).json({ error: 'User not found' });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/users/:referralCode/referrals', async (req, res) => {
    const { referralCode } = req.params;
    try {
        const result = await pool.query('SELECT name, email, referral_code FROM users WHERE referred_by = $1', [referralCode]);
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/users/:referralCode/coins', async (req, res) => {
    const { referralCode } = req.params;
    try {
        const result = await pool.query('SELECT rave_coins FROM users WHERE referral_code = $1', [referralCode]);
        if (result.rows.length > 0) {
            res.json(result.rows[0]);
        } else {
            res.status(404).json({ error: 'User not found' });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/admin/users/search', authenticateAdmin, async (req, res) => {
    const { query } = req.query;
    try {
        const result = await pool.query('SELECT * FROM users WHERE name ILIKE $1 OR email ILIKE $1 OR referral_code ILIKE $1', [`%${query}%`]);
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.put('/admin/users/:id/coins', authenticateAdmin, async (req, res) => {
    const { id } = req.params;
    const { coins } = req.body;
    try {
        await pool.query('UPDATE users SET rave_coins = $1 WHERE id = $2', [coins, id]);
        res.sendStatus(204);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/admin/referrals', authenticateAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT referred_by, COUNT(*) FROM users WHERE referred_by IS NOT NULL GROUP BY referred_by');
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/admin/referrals/:referralCode', authenticateAdmin, async (req, res) => {
    const { referralCode } = req.params;
    try {
        const result = await pool.query('SELECT name, email FROM users WHERE referred_by = $1', [referralCode]);
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

const PORT = process.env.PORT || 5001;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

app.get('/admin/referrals/:referralCode', authenticateAdmin, async (req, res) => {
    const { referralCode } = req.params;
    try {
        const result = await pool.query('SELECT name, email FROM users WHERE referred_by = $1', [referralCode]);
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

const PORT = process.env.PORT || 5001;
const server = app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

module.exports = server;

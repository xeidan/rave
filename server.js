require('dotenv').config();


const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult, param } = require('express-validator');

const app = express();
app.use(express.json());

// Database Connection
const { Pool } = require('pg');
const { parse } = require('pg-connection-string');

let pool;

if (process.env.DATABASE_URL) {
    // Heroku or other environment with DATABASE_URL
    const pgconfig = parse(process.env.DATABASE_URL);
    pool = new Pool(pgconfig);
} else {
    // Local development (or if you have other setup)
    pool = new Pool({
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        host: process.env.DB_HOST,
        port: process.env.DB_PORT,
        database: process.env.DB_DATABASE,
    });
}


    // ... get user data from req.body ...
    app.post('/users', async (req, res) => {
        const { name, email } = req.body; // Extract user data from req.body
    
        if (!name || !email) {
            return res.status(400).send('Name and email are required.');
        }
    
        try {
            await pool.query('INSERT INTO users (name, email) VALUES ($1, $2)', [name, email]);
            res.status(201).send('User signed up!');
        } catch (err) {
            console.error(err);
            res.status(500).send('Error signing up.');
        }
    });

// Basic route for testing
app.get('/', (req, res) => {
    res.send('Rave Waitlist API');
});

// Functions for hashing passwords, generating and verifying tokens
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

// Admin Login Endpoint
app.post('/admin/login', async (req, res) => {
    const { username, password } = req.body;
    const client = await pool.connect();
    try {
        const result = await client.query(
            'SELECT * FROM admin_users WHERE username = $1',
            [username]
        );
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

// Admin Authentication Middleware
function authenticateAdmin(req, res, next) {
    const authHeader = req.headers.authorization;
    console.log("Authorization Header: ", authHeader); //Log the header.
    if (authHeader) {
        const token = authHeader.split(' ')[1];
        console.log("Extracted Token: ", token); //Log the extracted token.
        const user = verifyToken(token);
        console.log("Verified User: ", user); // Log the result of the verification.
        if (user) {
            req.user = user;
            next();
        } else {
            res.sendStatus(403); // Forbidden
        }
    } else {
        res.sendStatus(401); // Unauthorized
    }
}

// User Endpoint 
app.post('/users', [
    body('name').notEmpty().withMessage('Name is required'),
    body('email').isEmail().withMessage('Invalid email address'),
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

        const referralCode = generateReferralCode(); // Generate referral code here

        await client.query('INSERT INTO users (name, email, referral_code, referred_by) VALUES ($1, $2, $3, $4)', [name, email, referralCode, referred_by]);

        await client.query('COMMIT');
        res.status(201).json({ message: 'User signed up successfully' });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    } finally {
        client.release();
    }
});


// Get All Users Endpoint
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

// Update User Position Endpoint
app.put('/admin/users/:id/position',
    authenticateAdmin,
    [
        param('id').isInt().withMessage('User ID must be an integer.'),
        body('position').isInt().withMessage('Position must be an integer.'),
    ],
    async (req, res) => {

        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { id } = req.params;
        const { position } = req.body;

        const client = await pool.connect();
        try {
            await client.query('UPDATE users SET position = $1 WHERE id = $2', [
                position,
                id,
            ]);
            res.sendStatus(204);
        } catch (err) {
            console.error(err);
            return res.status(500).json({ error: err.message || 'Internal server error' });
        } finally {
            client.release();
        }
    });

// Delete User Endpoint
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

//Referral Code Generation Function
function generateReferralCode() {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let referralCode = '';
    for (let i = 0; i < 8; i++) {
        referralCode += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return referralCode;
}

// Create initial Admin User (run once)
async function createAdminUser(username, password) {
    const hashedPassword = await hashPassword(password);
    const client = await pool.connect();
    try {
        const result = await client.query(
            'INSERT INTO admin_users (username, password) VALUES ($1, $2) RETURNING *',
            [username, hashedPassword]
        );
        return result.rows[0];
    } catch (err) {
        console.error(err);
        throw err;
    } finally {
        client.release();
    }
}

//run this once.
// createAdminUser('daniel', 'ZEIDAN')
//     .then(() => console.log('Admin user created'))
//     .catch((err) => console.error('Error creating admin user:', err));

const PORT = process.env.PORT || 5001;
const server = app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

module.exports = server;

// Reward user 10 rave coins upon referral
app.post('/users', async (req, res) => {
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

        await client.query('INSERT INTO users (name, email, referral_code, referred_by) VALUES ($1, $2, $3, $4)', [name, email, referral_code, referred_by]);

        await client.query('COMMIT');
        res.status(201).json({ message: 'User signed up successfully' });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    } finally {
        client.release();
    }
});


// User Referral Code
app.get('/users/:referralCode', [
    param('referralCode').isAlphanumeric().withMessage('Referral code must be alphanumeric'),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    
});

//User Position Check
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

// User Referrals
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

// User Coins
app.get('/users/:referralCode/coins', async (req, res) => {
    const { referralCode } = req.params;
    try {
        const result = await pool.query('SELECT rave_coins FROM users WHERE referral_code = $1', [referralCode]);
        if(result.rows.length > 0){
            res.json(result.rows[0]);
        } else {
            res.status(404).json({error: "User not found"})
        }

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// User Search
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


// Update User Coins
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

// Get all referrals
app.get('/admin/referrals', authenticateAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT referred_by, COUNT(*) FROM users WHERE referred_by IS NOT NULL GROUP BY referred_by');
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get Referrals by Code
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


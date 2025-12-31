const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://frontend-theta-lyart-52.vercel.app';

// Middleware
// Replace your old app.use(cors()) block with this:
app.use(cors({
  origin: [
    'https://frontend-theta-lyart-52.vercel.app', // Your NEW Vercel URL
    'http://localhost:3000'                      // For local testing
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));
app.use(express.json());

// PostgreSQL connection
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT || 5432,
});

let transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: Number(process.env.SMTP_PORT) === 465,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

let EMAIL_ENABLED = true;
let SMTP_VERIFY_ERROR = null;
let ACTIVE_SMTP_PORT = Number(process.env.SMTP_PORT || 587);
let ACTIVE_SMTP_SECURE = Number(process.env.SMTP_PORT) === 465;

const RESEND_API_KEY = process.env.RESEND_API_KEY || null;
const RESEND_FROM = process.env.RESEND_FROM || process.env.EMAIL_FROM || 'onboarding@resend.dev';

const EMAIL_PROVIDER = RESEND_API_KEY ? 'resend' : 'smtp';
if (EMAIL_PROVIDER === 'smtp') {
  if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS) {
    EMAIL_ENABLED = false;
    SMTP_VERIFY_ERROR = 'Missing SMTP configuration';
  }
} else {
  EMAIL_ENABLED = true;
  SMTP_VERIFY_ERROR = null;
}

const buildVerificationEmailHTML = (verifyLink) => {
  const brand = 'MedConsult Pro';
  return (
    '<!doctype html>' +
    '<html lang="en">' +
    '<head>' +
    '<meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    '<title>Email Verification</title>' +
    '</head>' +
    '<body style="margin:0;padding:0;background:#f7fafc;font-family:Inter,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1a202c;">' +
    '<table role="presentation" style="width:100%;border-collapse:collapse;background:#f7fafc;"><tr><td align="center" style="padding:24px;">' +
    '<table role="presentation" style="width:100%;max-width:560px;border-collapse:collapse;background:#ffffff;border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,0.06);overflow:hidden;">' +
    '<tr><td style="padding:24px 24px 8px 24px;text-align:center;background:#0ea5e9;color:#ffffff;">' +
    '<div style="font-weight:700;font-size:20px;letter-spacing:0.2px;">' + brand + '</div>' +
    '</td></tr>' +
    '<tr><td style="padding:24px 24px 0 24px;">' +
    '<h1 style="margin:0 0 12px 0;font-size:20px;line-height:28px;font-weight:700;color:#111827;">Verify your email</h1>' +
    '<p style="margin:0 0 16px 0;font-size:14px;line-height:22px;color:#374151;">Thanks for signing up. Please confirm your email to continue.</p>' +
    '</td></tr>' +
    '<tr><td style="padding:8px 24px 24px 24px;">' +
    '<a href="' + verifyLink + '" style="display:inline-block;background:#0ea5e9;color:#ffffff;text-decoration:none;font-weight:600;border-radius:8px;padding:12px 18px;">Verify Email</a>' +
    '<p style="margin:16px 0 0 0;font-size:12px;color:#6b7280;">If the button does not work, copy and paste this link:</p>' +
    '<p style="margin:4px 0 0 0;font-size:12px;color:#2563eb;word-break:break-all;"><a href="' + verifyLink + '" style="color:#2563eb;text-decoration:underline;">' + verifyLink + '</a></p>' +
    '</td></tr>' +
    '<tr><td style="padding:16px 24px;text-align:center;border-top:1px solid #e5e7eb;font-size:12px;color:#6b7280;">' +
    'This link expires in 24 hours.' +
    '</td></tr>' +
    '</table>' +
    '</td></tr></table>' +
    '</body>' +
    '</html>'
  );
};

const sendVerification = async (to, verifyLink) => {
  try {
    if (EMAIL_PROVIDER === 'resend' && RESEND_API_KEY) {
      const payload = JSON.stringify({
        from: RESEND_FROM,
        to,
        subject: 'Verify your email',
        text: `Verify your email: ${verifyLink}`,
        html: buildVerificationEmailHTML(verifyLink)
      });
      const ok = await new Promise((resolve) => {
        const req = require('https').request({
          hostname: 'api.resend.com',
          path: '/emails',
          method: 'POST',
          headers: {
            Authorization: `Bearer ${RESEND_API_KEY}`,
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload)
          }
        }, (res) => {
          let data = '';
          res.on('data', (chunk) => { data += chunk; });
          res.on('end', () => {
            const success = res.statusCode >= 200 && res.statusCode < 300;
            if (!success) SMTP_VERIFY_ERROR = `Resend error ${res.statusCode}`;
            resolve(success);
          });
        });
        req.on('error', (err) => {
          SMTP_VERIFY_ERROR = err && err.message ? err.message : String(err);
          resolve(false);
        });
        req.write(payload);
        req.end();
      });
      if (ok) return true;
    }
    if (EMAIL_PROVIDER === 'smtp' && EMAIL_ENABLED) {
      const info = await transporter.sendMail({
        from: process.env.EMAIL_FROM || process.env.SMTP_USER,
        to,
        subject: 'Verify your email',
        text: `Verify your email: ${verifyLink}`,
        html: buildVerificationEmailHTML(verifyLink)
      });
      return !!(info && info.messageId);
    }
    return false;
  } catch (e) {
    SMTP_VERIFY_ERROR = e && e.message ? e.message : String(e);
    return false;
  }
};

const runMigrations = async () => {
  try {
    await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT FALSE');
    await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verification_token TEXT');
    await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verification_expires TIMESTAMP WITH TIME ZONE');
  } catch (e) {
    console.error(e);
  }
};
runMigrations();

// JWT secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this';

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Sign up endpoint
app.post('/api/auth/signup', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    // Validate input
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Check if user already exists
    const userCheck = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email.toLowerCase()]
    );

    if (userCheck.rows.length > 0) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert new user
    const result = await pool.query(
      'INSERT INTO users (name, email, password, created_at) VALUES ($1, $2, $3, NOW()) RETURNING id, name, email, created_at',
      [name, email.toLowerCase(), hashedPassword]
    );

    const user = result.rows[0];

    const emailToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
    await pool.query(
      'UPDATE users SET email_verified = COALESCE(email_verified, false), email_verification_token = $1, email_verification_expires = $2 WHERE id = $3',
      [emailToken, expiresAt, user.id]
    );
    const base = process.env.VERIFICATION_BASE_URL || `http://localhost:${PORT}`;
    const verifyLink = `${base}/api/auth/verify-email?token=${encodeURIComponent(emailToken)}&email=${encodeURIComponent(user.email)}`;
    const sent = await sendVerification(user.email, verifyLink);

    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json(Object.assign({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        createdAt: user.created_at
      },
      verificationSent: !!sent
    }, sent ? {} : { verifyLink, reason: SMTP_VERIFY_ERROR || 'Email disabled' }));
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Server error during signup' });
  }
});

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Validate input
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find user
    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email.toLowerCase()]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = result.rows[0];

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    if (!user.email_verified) {
      return res.status(403).json({ error: 'Email not verified' });
    }

    // Generate JWT token - INSIDE try block
    const token = jwt.sign(
      { id: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    // Send response - INSIDE try block
    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        sessions: user.sessions || 0,
        totalMinutes: user.total_minutes || 0,
        weeklyMinutes: user.weekly_minutes || 0,
        createdAt: user.created_at
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error during login' });
  }
});

app.get('/api/auth/verify-email', async (req, res) => {
  const { token, email } = req.query;
  if (!token || !email) {
    return res.status(400).json({ error: 'Invalid verification link' });
  }
  try {
    const result = await pool.query(
      'SELECT id, email_verification_token, email_verification_expires FROM users WHERE email = $1',
      [email.toLowerCase()]
    );
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid verification request' });
    }
    const user = result.rows[0];
    if (!user.email_verification_token || user.email_verification_token !== token) {
      return res.status(400).json({ error: 'Invalid verification token' });
    }
    if (user.email_verification_expires && new Date(user.email_verification_expires) < new Date()) {
      return res.status(400).json({ error: 'Verification token expired' });
    }
    await pool.query(
      'UPDATE users SET email_verified = true, email_verification_token = NULL, email_verification_expires = NULL WHERE id = $1',
      [user.id]
    );
    res.redirect(`${FRONTEND_URL}?verified=1`);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error during verification' });
  }
});

app.post('/api/auth/resend-verification', async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Email required' });
  }
  try {
    const result = await pool.query(
      'SELECT id, email_verified FROM users WHERE email = $1',
      [email.toLowerCase()]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    const user = result.rows[0];
    if (user.email_verified) {
      return res.json({ success: true });
    }
    const emailToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
    await pool.query(
      'UPDATE users SET email_verification_token = $1, email_verification_expires = $2 WHERE id = $3',
      [emailToken, expiresAt, user.id]
    );
    const base = process.env.VERIFICATION_BASE_URL || `http://localhost:${PORT}`;
    const verifyLink = `${base}/api/auth/verify-email?token=${encodeURIComponent(emailToken)}&email=${encodeURIComponent(email.toLowerCase())}`;
    const sent = await sendVerification(email.toLowerCase(), verifyLink);
    res.json(Object.assign({ success: true, verificationSent: !!sent }, sent ? {} : { verifyLink, reason: SMTP_VERIFY_ERROR || 'Email disabled' }));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error resending verification' });
  }
});

app.get('/health/email', (req, res) => {
  res.json({ enabled: EMAIL_ENABLED });
});
app.get('/health/email/details', (req, res) => {
  res.json({
    enabled: EMAIL_ENABLED,
    provider: EMAIL_PROVIDER,
    resend_present: !!RESEND_API_KEY,
    from: RESEND_FROM || process.env.EMAIL_FROM || null,
    host_present: !!process.env.SMTP_HOST,
    user_present: !!process.env.SMTP_USER,
    pass_present: !!process.env.SMTP_PASS,
    port: ACTIVE_SMTP_PORT,
    secure: ACTIVE_SMTP_SECURE,
    verification_base_url: process.env.VERIFICATION_BASE_URL || null,
    last_verify_error: SMTP_VERIFY_ERROR
  });
});

app.post('/api/auth/debug-send', async (req, res) => {
  const { email } = req.body || {};
  console.log('1. Received email:', email); // ADD
  
  if (!email) return res.status(400).json({ error: 'Email required' });
  
  try {
    const token = crypto.randomBytes(16).toString('hex');
    const base = process.env.VERIFICATION_BASE_URL || `http://localhost:${PORT}`;
    const link = `${base}/api/auth/verify-email?token=${encodeURIComponent(token)}&email=${encodeURIComponent(email.toLowerCase())}`;
    
    console.log('2. Generated link:', link); // ADD
    console.log('3. About to call sendVerification'); // ADD
    
    const sent = await sendVerification(email.toLowerCase(), link);
    
    console.log('4. sendVerification result:', sent); // ADD
    
    res.json(Object.assign({ success: true, verificationSent: !!sent }, sent ? {} : { verifyLink: link, reason: SMTP_VERIFY_ERROR || 'Email disabled' }));
  } catch (e) {
    console.error('Debug send error:', e);
    res.status(500).json({ error: 'Debug send failed', details: e.message }); // ADD e.message
  }
});

// Get user stats
app.get('/api/user/stats', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT sessions, total_minutes, weekly_minutes FROM users WHERE id = $1',
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      sessions: result.rows[0].sessions || 0,
      totalMinutes: result.rows[0].total_minutes || 0,
      weeklyMinutes: result.rows[0].weekly_minutes || 0
    });
  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({ error: 'Server error getting stats' });
  }
});

// Update user stats (after session ends)
app.post('/api/user/stats', authenticateToken, async (req, res) => {
  const { sessionDuration } = req.body;
  // Use Math.ceil so short calls (e.g. 10s) count as at least 1 minute
  const minutes = Math.ceil(sessionDuration / 60);

  try {
    const result = await pool.query(
      `UPDATE users 
       SET sessions = sessions + 1, 
           total_minutes = total_minutes + $1,
           weekly_minutes = weekly_minutes + $1 
       WHERE id = $2 
       RETURNING sessions, total_minutes AS "totalMinutes", weekly_minutes AS "weeklyMinutes"`,
      [minutes, req.user.id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

// Get current user info
app.get('/api/user/me', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, email, sessions, total_minutes, weekly_minutes, created_at FROM users WHERE id = $1',
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = result.rows[0];
    res.json({
      id: user.id,
      name: user.name,
      email: user.email,
      sessions: user.sessions || 0,
      totalMinutes: user.total_minutes || 0,  // Convert to camelCase HERE
      weeklyMinutes: user.weekly_minutes || 0,
      createdAt: user.created_at
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Server error getting user info' });
  }
});
// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'OK' });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

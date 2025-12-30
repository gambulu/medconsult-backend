const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

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

    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        createdAt: user.created_at
      }
    });
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

// Get user stats
app.get('/api/user/stats', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT sessions, total_minutes FROM users WHERE id = $1',
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      sessions: result.rows[0].sessions || 0,
      totalMinutes: result.rows[0].total_minutes || 0
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
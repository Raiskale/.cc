const express = require('express');
const app = express();
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const path = require('path');
const session = require('express-session');


app.use(session({
  secret: 'your-strong-secret', // Replace with a secure secret in production
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 } // 1 day
}));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

app.get('/dash.html', (req, res, next) => {
  if (!req.session.userId) {
    return res.redirect('/index.html'); // Not logged in, redirect to login page
  }
  next(); // Logged in, continue to serve dash.html
});


app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Registration route
app.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const hash = await bcrypt.hash(password, 10);

    await pool.query(
      'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3)',
      [username, email, hash]
    );

    // After registering, redirect user back to login page (index.html)
    res.redirect('/');
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).send('Server error');
  }
});

// Login route
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).send('Invalid email or password');
    }

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);

    if (!validPassword) {
      return res.status(401).send('Invalid email or password');
    }

    // Password valid, save user ID in session
    req.session.userId = user.id;

    // Redirect to dashboard page (dash.html)
    res.redirect('/dash.html');
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).send('Server error');
  }
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));


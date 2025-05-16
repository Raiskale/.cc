const express = require('express');
const app = express();
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const session = require('express-session');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: 'your-strong-secret',  // Replace with a real strong secret in production!
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 } // 1 day
}));

// Protect dash.html route
app.use('/dash.html', (req, res, next) => {
  if (!req.session.userId) {
    return res.redirect('/index.html');
  }
  next();
});

app.use(express.static('public'));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// Registration route
app.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const emailLower = email.toLowerCase();
    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3)',
      [username, emailLower, hash]
    );
    res.redirect('/index.html'); // redirect to login page
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).send('Server error');
  }
});

// Login route
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const emailLower = email.toLowerCase();
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [emailLower]);

    if (result.rows.length === 0) {
      return res.status(401).send('Invalid email or password');
    }

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);

    if (!validPassword) {
      return res.status(401).send('Invalid email or password');
    }

    req.session.userId = user.id;
    res.redirect('/dash.html');
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).send('Server error');
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

const express = require('express');
const app = express();
const { Pool } = require('pg');

const bcrypt = require('bcrypt');
const path = require('path');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});


app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  const hash = await bcrypt.hash(password, 10);

  await pool.query(
    'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3)',
    [username, email, hash]
  );
  res.send('Registered!');
});

app.listen(3000, () => console.log('Server running on http://localhost:3000'));

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Find user by email
    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      // No user found with that email
      return res.status(401).send('Invalid email or password');
    }

    const user = result.rows[0];

    // Compare the provided password with the stored hash
    const validPassword = await bcrypt.compare(password, user.password_hash);

    if (!validPassword) {
      return res.status(401).send('Invalid email or password');
    }

    // If password is valid, redirect to dash.html
    res.redirect('/dash.html');
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).send('Server error');
  }
});


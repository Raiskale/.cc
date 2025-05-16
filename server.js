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

// **LOGIN ROUTE**
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await pool.query(
      'SELECT password_hash FROM users WHERE username = $1',
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(400).send('User not found');
    }

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);

    if (match) {
      res.send('Login successful!');
      // You can add session or token logic here later
    } else {
      res.status(400).send('Incorrect password');
    }
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});



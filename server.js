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

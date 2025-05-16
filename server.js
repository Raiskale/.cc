app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Get user by username
    const result = await pool.query(
      'SELECT * FROM users WHERE username = $1',
      [username]
    );

    if (result.rows.length === 0) {
      // User not found
      return res.status(401).send('Invalid username or password');
    }

    const user = result.rows[0];

    // Compare password hash
    const match = await bcrypt.compare(password, user.password_hash);

    if (!match) {
      // Password incorrect
      return res.status(401).send('Invalid username or password');
    }

    // Password is correct - redirect to dashboard
    res.redirect('/dash.html');  // Because 'public' folder is static

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).send('Server error');
  }
});

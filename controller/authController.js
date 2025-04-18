const pool = require('../db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const SECRET = 'your_secret_key'; // Put this in .env for production

exports.register = async (req, res) => {
    const { name, email, password } = req.body;
    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      const result = await pool.query(
        'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING *',
        [name, email, hashedPassword]
      );
  
      const user = result.rows[0];
      const token = jwt.sign({ userId: user.id }, SECRET, { expiresIn: '1h' });
  
      const userWithoutPassword = {
        id: user.id,
        name: user.name,
        email: user.email
      };
  
      res.status(201).json({ token, user: userWithoutPassword });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  };
  

  exports.login = async (req, res) => {
    const { email, password } = req.body;
    try {
      const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
      const user = result.rows[0];
      if (!user) return res.status(400).json({ error: 'Invalid credentials' });
  
      const match = await bcrypt.compare(password, user.password);
      if (!match) return res.status(400).json({ error: 'Invalid credentials' });
  
      const token = jwt.sign({ userId: user.id }, SECRET, { expiresIn: '1h' });
  
      // Send user info without password
      const userWithoutPassword = {
        id: user.id,
        name: user.name,
        email: user.email
      };
  
      res.json({ token, user: userWithoutPassword });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  };
  
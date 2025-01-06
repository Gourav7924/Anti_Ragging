require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');

const app = express();
app.use(cors()); // Enable CORS for all routes
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
const PORT = process.env.PORT || 5000;

// Serve static files from the 'public' directory
app.use(express.static('public'));

// Middleware for input validation
const validateInput = (req, res, next) => {
  const { identifier, passphrase } = req.body;
  if (!identifier || !passphrase) {
    return res.status(400).json({ error: 'Identifier and password are required' });
  }
  next();
};

// Register User (Sign-Up)
app.post('/signup', async (req, res) => {
  // User registration logic
});

// Login Route
app.post('/login', validateInput, async (req, res) => {
  // Login logic
});

// Complaint Registration Route
app.post('/complaints', authenticateToken, async (req, res) => {
  // Complaint registration logic
});

// Middleware for Token Authentication
function authenticateToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Default Route to serve the login page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'home.html'));
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

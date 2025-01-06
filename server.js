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
  const {
    title,
    full_name,
    street,
    additional_info,
    zip,
    place,
    country,
    code,
    phone,
    email,
    password,
    agreed_to_terms
  } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const agreed = agreed_to_terms === 'on' ? true : false;

    const { data, error } = await supabase
      .from('Users')
      .insert([{
        title,
        full_name,
        street,
        additional_info,
        zip,
        place,
        country,
        code,
        phone,
        email,
        password: hashedPassword,
        agreed_to_terms: agreed
      }]);

    if (error) throw error;
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Login Route
app.post('/login', validateInput, async (req, res) => {
  const { identifier, passphrase } = req.body;

  try {
    // Search for user by email or username
    const { data, error } = await supabase
      .from('Users')
      .select()
      .or(`email.eq.${identifier},username.eq.${identifier}`)
      .single();

    if (!data || error) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Verify password
    const validPassword = await bcrypt.compare(passphrase, data.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Incorrect password' });
    }

    // Generate JWT token
    const token = jwt.sign({ user_id: data.user_id, title: data.title }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    res.status(500).json({ error: 'An error occurred during login' });
  }
});

// Complaint Registration Route
app.post('/complaints', authenticateToken, async (req, res) => {
  const { complaint_name, victim_name, mobile, email, gender, caste, state, details } = req.body;

  if (req.user.title !== 'Student') {
    return res.status(403).json({ error: 'Only students can file complaints' });
  }

  try {
    const { error } = await supabase.from('Complaints').insert([{
      user_id: req.user.user_id,
      complaint_name,
      victim_name,
      mobile,
      email,
      gender,
      caste,
      state,
      details
    }]);

    if (error) throw error;
    res.json({ message: 'Complaint submitted successfully' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
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
  res.sendFile(path.join(__dirname, 'public', 'home.html')); // Serve login.html as the homepage
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

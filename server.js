require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
const PORT = process.env.PORT || 5000;

// Register User (Sign-Up)
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

    const hashedPassword = await bcrypt.hash(password, 10);
    const agreed = agreed_to_terms === 'on' ? true : false;  // Handle checkbox

    const { data, error } = await supabase
        .from('Users')
        .insert([
            {
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
            }
        ]);

    if (error) {
        return res.status(400).json(error);
    }
    res.status(201).json({ message: 'User registered successfully' });
});

// Login Route
app.post('/login', async (req, res) => {
    const { username, passphrase } = req.body;
    const { data, error } = await supabase.from('Users').select().eq('email', username).single();

    if (!data || error) {
        return res.status(400).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(passphrase, data.password);
    if (!validPassword) {
        return res.status(401).json({ error: 'Incorrect password' });
    }

    const token = jwt.sign({ user_id: data.user_id, title: data.title }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
});

// Complaint Registration Route
app.post('/complaints', authenticateToken, async (req, res) => {
    const { complaint_name, victim_name, mobile, email, gender, caste, state, details } = req.body;

    if (req.user.title !== 'Student') {
        return res.status(403).json({ error: 'Only students can file complaints' });
    }

    const { error } = await supabase.from('Complaints').insert([
        {
            user_id: req.user.user_id,
            complaint_name,
            victim_name,
            mobile,
            email,
            gender,
            caste,
            state,
            details
        }
    ]);

    if (error) {
        return res.status(400).json(error);
    }
    res.json({ message: 'Complaint submitted successfully' });
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

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

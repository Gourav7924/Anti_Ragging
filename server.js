require('dotenv').config(); 
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const cookieParser = require('cookie-parser'); // Middleware to parse cookies
const { createClient } = require('@supabase/supabase-js');
const path = require('path');

const app = express();
app.use(cors()); // Enable CORS for all routes
app.use(express.urlencoded({ extended: true })); // Parse URL-encoded data
app.use(express.json()); // Parse JSON data
app.use(cookieParser()); // Use cookie-parser to handle cookies

// Initialize Supabase client
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
const PORT = process.env.PORT || 5000;

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// Middleware for debugging requests
app.use((req, res, next) => {
    console.log(`${req.method} request to ${req.url}`);
    console.log('Request Body:', req.body);
    next();
});

// Middleware for token authentication
function authenticateToken(req, res, next) {
    const token = req.cookies.token; // Extract token from cookies
    if (!token) {
        console.error("Authorization token missing");
        return res.status(401).json({ error: 'Unauthorized: Token missing' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            console.error("Token verification failed:", err.message);
            return res.status(403).json({ error: 'Forbidden: Invalid token' });
        }
        console.log("Token verified, user:", user);
        req.user = user;
        next();
    });
}

// Route: Serve Sign-Up Page
app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'SignUp.html')); // Adjust filename if necessary
});

// Route: User Sign-Up
app.post('/signup', async (req, res) => {
    const {
        title,
        full_name,
        street,
        additional_info,
        zip,
        place,
        country,
        phone,
        email,
        password,
        agreed_to_terms
    } = req.body;

    try {
        console.log("Processing sign-up...");
        if (!title || !full_name || !street || !zip || !place || !country || !phone || !email || !password) {
            throw new Error("All fields are required.");
        }

        const { data: existingUser, error: emailCheckError } = await supabase
            .from('users')
            .select('email')
            .eq('email', email)
            .single();

        if (existingUser) {
            throw new Error("Email is already registered.");
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert user into the database
        const { data, error } = await supabase
            .from('users')
            .insert([{
                title,
                full_name,
                street,
                additional_info: additional_info || null,
                zip,
                place,
                country,
                phone,
                email,
                password: hashedPassword,
                agreed_to_terms: agreed_to_terms === 'on'
            }]);

        if (error) {
            console.error("Supabase Insert Error:", JSON.stringify(error, null, 2));
            throw new Error("Failed to register user");
        }

        console.log("User inserted successfully:", data);
        res.redirect('/login');
    } catch (error) {
        console.error("Sign-Up Error:", error.message);
        res.status(400).json({ error: error.message });
    }
});

// Route: Serve Login Page
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Route: User Login
app.post('/login', async (req, res) => {
    const { identifier, passphrase } = req.body;

    if (!identifier || !passphrase) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    try {
        console.log("Processing login...");
        const { data, error } = await supabase
            .from('users')
            .select('email, password, user_id, title')
            .eq('email', identifier)
            .single();

        if (error || !data) {
            console.error("Supabase Query Error:", JSON.stringify(error, null, 2));
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        const validPassword = await bcrypt.compare(passphrase, data.password);
        if (!validPassword) {
            console.error("Incorrect password for user:", identifier);
            return res.status(401).json({ error: 'Incorrect password' });
        }

        const token = jwt.sign(
            { user_id: data.user_id, title: data.title },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        console.log("Login successful for user:", data.email);

        // Set token as an HTTP-only cookie
        res.cookie('token', token, {
            httpOnly: true,
            secure: false, // Use `true` if using HTTPS
            sameSite: 'strict'
        });

        // Send the response after setting the cookie
        return res.json({ message: 'Login successful' });
    } catch (error) {
        console.error("Login Error:", error.message);
        return res.status(500).json({ error: 'An error occurred during login' });
    }
});
// Route: Complaint Registration
app.post('/complaints', authenticateToken, async (req, res) => {
    if (req.user.title !== 'Student') {
        console.error("Unauthorized user tried to file a complaint");
        return res.status(403).json({ error: 'Only students can file complaints' });
    }

    const {
        complaint_name,
        victim_name,
        mobile,
        email,
        gender,
        caste,
        state,
        college_name,
        zip,
        address,
        details
    } = req.body;
    if (!complaint_name || !victim_name || !mobile || !email || !state || !college_name || !zip || !address || !details) {
        return res.status(400).json({ error: 'All fields are required for complaint registration.' });
    }

    try {
        console.log("Processing complaint submission...");
        const { error } = await supabase.from('complaints').insert([{
            user_id: req.user.user_id,
            complaint_name,
            victim_name,
            mobile,
            email,
            gender,
            caste,
            state,
            college_name,
            zip,
            address,
            details
        }]);

        if (error) {
            console.error("Supabase Insert Error:", error);
            throw new Error("Failed to submit complaint");
        }

        console.log("Complaint submitted successfully");
        res.status(201).json({ message: 'Complaint submitted successfully' });
    } catch (error) {
        console.error("Complaint Submission Error:", error.message);
        res.status(400).json({ error: error.message });
    }
});

// Route: Track Complaint by Mobile Number
app.get('/track-complaint', async (req, res) => {
    const { mobile } = req.query;

    if (!mobile) {
        return res.status(400).json({ error: 'Mobile number is required' });
    }

    try {
        console.log("Fetching complaint status for mobile:", mobile);
        const { data, error } = await supabase
            .from('complaints')
            .select('complaint_name, status, details, submitted_at')
            .eq('mobile', mobile);

        if (error) {
            console.error("Supabase Query Error:", error);
            throw new Error("Error fetching complaint status");
        }

        if (data.length === 0) {
            return res.status(404).json({ message: 'No complaints found for this mobile number' });
        }

        // Format the submitted_at field as an ISO string
        const formattedData = data.map(complaint => ({
            ...complaint,
            submitted_at: new Date(complaint.submitted_at).toISOString(), // Convert to ISO format
        }));

        console.log("Complaint status fetched successfully:", formattedData);
        res.status(200).json({ complaints: formattedData });
    } catch (error) {
        console.error("Error in complaint tracking:", error.message);
        res.status(500).json({ error: error.message });
    }
});

// Route: Serve Home Page
app.get('/home', authenticateToken, (req, res) => {
    console.log("User accessing /home:", req.user);
    res.sendFile(path.join(__dirname, 'public', 'home.html'));
});

// Route: Serve Home Page Without Authentication (Test Only)
// Uncomment this route temporarily to test static file serving.
// app.get('/home', (req, res) => {
//     res.sendFile(path.join(__dirname, 'public', 'home.html'));
// });

// Route: Serve Home Page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'home.html'));
});

// Start the Server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`)); 
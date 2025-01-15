const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');
const dotenv = require('dotenv');

dotenv.config(); // Load environment variables

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(bodyParser.json());
app.use(express.static('public')); // Serve static files like the HTML page

// MySQL Database Connection
const db = mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root', // Use environment variable or default
    password: process.env.DB_PASSWORD || '', // Use environment variable or default
    database: process.env.DB_NAME || 'myp',
});

// Connect to the database
db.connect((err) => {
    if (err) {
        console.error('Error connecting to the database:', err);
        process.exit(1);
    }
    console.log('Connected to MySQL database.');
});

// Signup Endpoint
app.post(
    '/signup',
    [
        body('username').notEmpty().withMessage('Username is required'),
        body('email').isEmail().withMessage('Invalid email'),
        body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ success: false, errors: errors.array() });
        }

        const { username, email, password } = req.body;

        try {
            // Check if the user already exists
            db.query('SELECT * FROM users WHERE username = ? OR email = ?', [username, email], async (err, results) => {
                if (err) return res.status(500).json({ success: false, message: 'Database error' });

                if (results.length > 0) {
                    return res.status(400).json({ success: false, message: 'Username or email already exists' });
                }

                // Hash the password
                const hashedPassword = await bcrypt.hash(password, 10);

                // Insert the user into the database
                db.query(
                    'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                    [username, email, hashedPassword],
                    (err, results) => {
                        if (err) return res.status(500).json({ success: false, message: 'Database error' });

                        res.json({ success: true, message: 'Account created successfully!' });
                    }
                );
            });
        } catch (error) {
            res.status(500).json({ success: false, message: 'Internal server error' });
        }
    }
);

// Login Endpoint
app.post(
    '/login',
    [
        body('username').notEmpty().withMessage('Username is required'),
        body('password').notEmpty().withMessage('Password is required'),
    ],
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ success: false, errors: errors.array() });
        }

        const { username, password } = req.body;

        // Check if the user exists
        db.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
            if (err) return res.status(500).json({ success: false, message: 'Database error' });

            if (results.length === 0) {
                return res.status(400).json({ success: false, message: 'Invalid username or password' });
            }

            const user = results[0];

            // Compare the password
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.status(400).json({ success: false, message: 'Invalid username or password' });
            }

            res.json({ success: true, message: 'Login successful!' });
            req.session.user = { id: user.id, username: user.username };
            res.redirect('/dashbord');
        });
    }
);

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});

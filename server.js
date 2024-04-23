const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const mysql = require('mysql');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Secret key for JWT
const JWT_SECRET = 'randomkey';

// making sql connection
const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'class'
});

// connecting to mysql
connection.connect(err => {
    try {
        if (err) {
            throw new Error('Error connecting to MySQL database: ' + err);
        }
        console.log('Connected to MySQL database');
    } catch (err) {
        console.error(err.message);
    }
});

// validating email format using regex
function validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// checking password length and presence of special character
function validatePassword(password) {
    return password.length >= 7 && /[!@#$%^&*(),.?":{}|<>]/.test(password);
}

// verifying mobile number format
function validateMobileNumber(mobile_number) {
    const mobileRegex = /^[9]+\d{9}$/;
    return mobileRegex.test(mobile_number);
}

// Variable to store active sessions
let activeSessions = [];

// Login route
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    // Check if email and password are provided
    if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required" });
    }

    // Query to check if the user exists in the database
    const selectQuery = 'SELECT * FROM login WHERE email = ? AND password = ?';
    const values = [email, password];

    try {
        const results = await queryDatabase(selectQuery, values);
        if (results.length === 0) {
            return res.status(401).json({ error: "Invalid email or password" });
        }

        // Generate JWT token for authentication
        const token = jwt.sign({ email: results[0].email }, JWT_SECRET);

        // Store token and email in active sessions
        activeSessions.push({ token, email: results[0].email });

        res.json({ message: 'Login successful', token, email: results[0].email });

    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Logout route
app.post('/logout', async (req, res) => {
    const { email } = req.body;

    // Check if email is provided
    if (!email) {
        return res.status(400).json({ error: "Email is required for logout" });
    }

    // Find the session with the provided email
    const sessionIndex = activeSessions.findIndex(session => session.email === email);

    // Check if session exists
    if (sessionIndex === -1) {
        return res.status(404).json({ error: "Session not found" });
    }

    // Remove session from active sessions
    const { token } = activeSessions.splice(sessionIndex, 1)[0];

    res.json({ message: "Logout successful", email, token });
});

// Registration route
app.post('/register', async (req, res) => {
    const { name, email, address, password, mobile_number } = req.body;

    // Validate input fields
    if (!name || !email || !address || !password || !mobile_number) {
        return res.status(400).json({ error: "All fields are required" });
    }

    if (name.length < 3) {
        return res.status(400).json({ error: "Name must be at least 3 characters long" });
    }

    if (!validateEmail(email)) {
        return res.status(400).json({ error: "Invalid email format" });
    }

    if (address.length < 10) {
        return res.status(400).json({ error: "Address must be at least 10 characters long" });
    }

    if (!validatePassword(password)) {
        return res.status(400).json({ error: "Password must be at least 7 characters long and contain at least one special character" });
    }

    if (!validateMobileNumber(mobile_number)) {
        return res.status(400).json({ error: "Invalid mobile number" });
    }

    // Check if the email already exists in the database
    const emailExistsQuery = 'SELECT * FROM login WHERE email = ?';
    const emailExistsValues = [email];

    try {
        const emailExistsResult = await queryDatabase(emailExistsQuery, emailExistsValues);
        if (emailExistsResult.length > 0) {
            return res.status(400).json({ error: "Email already exists" });
        }
    } catch (err) {
        console.error(err.message);
        return res.status(500).json({ error: 'Internal server error' });
    }

    // Insert user data into the database
    const insertQuery = 'INSERT INTO login (name, email, address, password, mobile_number) VALUES (?, ?, ?, ?, ?)';
    const values = [name, email, address, password, mobile_number];

    try {
        await queryDatabase(insertQuery, values);
        res.json({ message: 'User registered successfully' });
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Function to execute SQL queries
function queryDatabase(query, values) {
    return new Promise((resolve, reject) => {
        connection.query(query, values, (err, results) => {
            if (err) {
                reject(err);
            } else {
                resolve(results);
            }
        });
    });
}

// Route to fetch users with a given mobile number
app.post('/users', async (req, res) => {
    const { mobile_number } = req.body;

    // Validate mobile number format
    if (!validateMobileNumber(mobile_number)) {
        return res.status(400).json({ error: "Invalid mobile number format" });
    }

    // Query to fetch users' names with the given mobile number
    const selectQuery = 'SELECT name FROM login WHERE mobile_number = ?';
    const values = [mobile_number];

    try {
        const users = await queryDatabase(selectQuery, values);
        const names = users.map(user => user.name);
        res.json(names);
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

//in case of successful connection to postman
app.get('/test', (req, res) => {
    res.send('connected successfully');
});

//checking if we have specified a port in env file, in our case we haven't so 3000 is used 
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
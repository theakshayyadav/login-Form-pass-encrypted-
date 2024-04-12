const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const mysql = require('mysql');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use("/assets", express.static('assets'));

const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'root123',
    database: 'nodejs'
});

connection.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL database: ' + err.stack);
        return;
    }
    console.log('Connected to MySQL database as id ' + connection.threadId);
});

// Secret key for JWT
const secretKey = 'your_secret_key'; // Replace 'your_secret_key' with your actual secret key

// Middleware to verify JWT token
function verifyToken(req, res, next) {
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(403).send('<script>alert("Token not provided."); window.location.href = "/";</script>');
    }

    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) {
            return res.status(401).send('<script>alert("Unauthorized access."); window.location.href = "/";</script>');
        }
        req.user = decoded;
        next();
    });
}

// Set up routes
app.get("/", function(req, res) {
    res.sendFile(path.join(__dirname, "index.html"));
});

// Handle sign-up form submission
app.post("/signup", function(req, res) {
    const userName = req.body.txt;
    const email = req.body.email;
    const password = req.body.pswd;

    if (!userName || !email || !password) {
        // Show an alert if sign-up form is not filled completely
        res.send('<script>alert("Please fill in all fields."); window.location.href = "/";</script>');
    } else {
        // Hash the password using bcrypt
        bcrypt.hash(password, 10, function(err, hash) {
            if (err) {
                console.error('Error hashing password:', err);
                res.status(500).send('<script>alert("Error while signing up."); window.location.href = "/";</script>');
            } else {
                // Insert the hashed password into the database
                connection.query("INSERT INTO signup_user(username, email, password) VALUES (?, ?, ?)", [userName, email, hash], function(error, results, fields) {
                    if (error) {
                        res.status(500).send('<script>alert("Error while signing up."); window.location.href = "/";</script>');
                    } else {
                        const token = jwt.sign({ username: userName, email: email }, secretKey, { expiresIn: '1h' });
                        res.json({ token: token });
                    }
                });
            }
        });
    }
});


// Handle login form submission
app.post("/login", function(req, res) {
    const username = req.body.username;
    const password = req.body.user_pass;

    if (!username || !password) {
        // Show an alert if login form is not filled completely
        res.send('<script>alert("Please fill in all fields."); window.location.href = "/";</script>');
    } else {
        // Check credentials against the database
        connection.query("SELECT * FROM signup_user WHERE username = ? AND password = ?", [username, password], function(error, results, fields) {
            if (error) {
                res.status(500).send('<script>alert("Error while logging in."); window.location.href = "/";</script>');
            } else if (results.length > 0) {
                const token = jwt.sign({ username: username }, secretKey, { expiresIn: '1h' });
                res.json({ token: token });
            } else {
                res.status(400).send('<script>alert("Invalid username or password."); window.location.href = "/";</script>');
            }
        });
    }
});

// Example of using the verifyToken middleware in a protected route
app.get("/welcome", verifyToken, function(req, res) {
    res.send('<script>alert("Welcome!");</script>');
});

// Set app port
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

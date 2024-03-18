
const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser'); 

const app = express();

// Serve static files from the 'dev' directory
app.use(express.static('dev'));

// Set the view engine to EJS
// app.set('view engine', 'ejs');

// Middleware to parse request body
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser()); // Use cookie parser middleware

// JWT secret key
const JWT_SECRET = 'magar'; 
const users = [];

app.post('/signup', (req, res) => {
    const email = req.body.email;
    const password = req.body.password;

    if (email && password) {
        const checkUser = users.find(userData => userData.email === email);

        if (checkUser) {
            res.send('Email already in use');
        } else {
            users.push({ email, password });
            console.log('User signed up:', email); 
                
            res.sendFile(path.join(__dirname, 'dev', 'login.html'));        }
    } else {
        res.status(400).send('Please fill in all details.'); 
    }
});

app.post('/login', (req, res) => {
    const email = req.body.email;
    const password = req.body.password;

    if (email && password) {
        const user = users.find(userData => userData.email === email && userData.password === password);

        if (user) {
            // Generate JWT token
            const token = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: "1h"  });
            res.cookie('token', token, { httpOnly: true });
            res.redirect('/protected-route');
        } else {
            res.status(401).send('Invalid email or password. Please try again.');
        }
    } else {
        res.status(400).send('Please fill in all details.'); 
    }
});

const authenticateJWT = (req, res, next) => {
    const token = req.cookies.token;

    if (!token) {
        return res.status(401).send('Unauthorized: No token provided');
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).send('Unauthorized: Invalid token');
        }
        // User is authenticated
        next();
    });
};

app.get('/protected-route', authenticateJWT, (req, res) => {
    console.log('Accessing protected route'); 
    res.sendFile(path.join(__dirname, 'dev','sucess.html'));
});

app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'dev', 'login.html'));
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'dev', 'form.html'));
});

const server = app.listen(5000, () => {
    console.log('Server is running on port 5000');
});


require('dotenv').config(); // Load environment variables from .env file

const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const axios = require('axios');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const crypto = require('crypto');
const User = require('./models/User');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(bodyParser.json());
app.use(cors());

// Environment variables
const PLAID_CLIENT_ID = process.env.PLAID_CLIENT_ID;
const PLAID_SECRET = process.env.PLAID_SECRET;
const PLAID_ENV = 'https://production.plaid.com';
const MONGODB_URI = process.env.MONGODB_URI;

// Dynamically generate JWT secret
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
console.log(`JWT Secret: ${JWT_SECRET}`);

// Connect to MongoDB
console.log(`Connecting to MongoDB at ${MONGODB_URI}`);
mongoose.connect(MONGODB_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => {
    console.error('MongoDB connection error:', err.message);
    process.exit(1); // Exit process with failure
  });

// Middleware to authenticate JWT
const authenticateJWT = (req, res, next) => {
  const token = req.header('Authorization');
  console.log('Authorization header:', token); // Add this line to log the token
  if (!token) return res.status(401).send('Access denied. No token provided.');

  try {
    const decoded = jwt.verify(token.split(' ')[1], JWT_SECRET);
    req.user = decoded;
    next();
  } catch (ex) {
    res.status(400).send('Invalid token.');
  }
};

// User registration
app.post('/signup', async (req, res) => {
  const { firstName, lastName, email, password } = req.body;
  try {
    const userExists = await User.findOne({ email });
    if (userExists) return res.status(400).send('User already exists.');

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ firstName, lastName, email, password: hashedPassword });
    await user.save();
    res.send('User registered successfully.');
  } catch (error) {
    console.error('Error during signup:', error.message);
    res.status(500).send('Server error.');
  }
});

// User login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).send('Invalid email or password.');

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).send('Invalid email or password.');

    const token = jwt.sign({ email: user.email }, JWT_SECRET);
    res.send({ token });
  } catch (error) {
    console.error('Error during login:', error.message);
    res.status(500).send('Server error.');
  }
});

// Fetch user information
app.get('/user', authenticateJWT, async (req, res) => {
  try {
    const user = await User.findOne({ email: req.user.email });
    if (!user) return res.status(400).send('User not found.');

    res.json({ firstName: user.firstName, lastName: user.lastName, email: user.email });
  } catch (error) {
    console.error('Error fetching user information:', error.message);
    res.status(500).send('Server error.');
  }
});

// Create Plaid link token
app.post('/create_link_token', authenticateJWT, async (req, res) => {
  try {
    console.log('Creating link token for user:', req.user.email);
    const response = await axios.post(`${PLAID_ENV}/link/token/create`, {
      client_id: PLAID_CLIENT_ID,
      secret: PLAID_SECRET,
      user: {
        client_user_id: req.user.email
      },
      client_name: 'Your App Name',
      products: ['transactions'],
      country_codes: ['US'],
      language: 'en'
    });
    res.json(response.data);
  } catch (error) {
    console.error('Error creating link token:', error.response ? error.response.data : error.message);
    res.status(500).send(error.response ? error.response.data : 'Internal Server Error');
  }
});

// Exchange public token
app.post('/exchange_public_token', authenticateJWT, async (req, res) => {
  try {
    const response = await axios.post(`${PLAID_ENV}/item/public_token/exchange`, {
      client_id: PLAID_CLIENT_ID,
      secret: PLAID_SECRET,
      public_token: req.body.public_token
    });

    const user = await User.findOneAndUpdate(
      { email: req.user.email },
      { accessToken: response.data.access_token },
      { new: true }
    );

    if (!user) {
      return res.status(400).send('User not found.');
    }

    res.json({ message: 'Token exchange successful' });
  } catch (error) {
    console.error('Error exchanging public token:', error.response ? error.response.data : error.message);
    res.status(500).send(error.response ? error.response.data : 'Internal Server Error');
  }
});

// Fetch transactions
app.get('/fetch_transactions', authenticateJWT, async (req, res) => {
  try {
    const user = await User.findOne({ email: req.user.email });
    if (!user || !user.accessToken) return res.status(400).send('No access token found.');

    const response = await axios.post(`${PLAID_ENV}/transactions/get`, {
      client_id: PLAID_CLIENT_ID,
      secret: PLAID_SECRET,
      access_token: user.accessToken,
      start_date: '2022-01-01',
      end_date: new Date().toISOString().split('T')[0]
    });
    res.json(response.data.transactions);
  } catch (error) {
    console.error('Error fetching transactions:', error.response ? error.response.data : error.message);
    res.status(500).send(error.response ? error.response.data : 'Internal Server Error');
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

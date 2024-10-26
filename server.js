// server.js
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
app.use(express.json());







mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/user-auth')
  .then(() => console.log("Connected to MongoDB"))
  .catch(err => console.error("Failed to connect to MongoDB", err));



// User model
const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model('User', UserSchema);

// Middleware for JWT verification
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).send('Access denied.');

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).send('Invalid token.');
    req.userId = decoded.id;
    next();
  });
};

// API Endpoints

// User registration
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  
  const newUser = new User({ email, password: hashedPassword });
  
  try {
    await newUser.save();
    res.status(201).send('User registered successfully.');
  } catch (error) {
    res.status(400).send('Error registering user: ' + error.message);
  }
});

// User login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  
  const user = await User.findOne({ email });
  if (!user) return res.status(400).send('Invalid credentials.');

  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) return res.status(400).send('Invalid credentials.');

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

// List users
app.get('/users', verifyToken, async (req, res) => {
  const users = await User.find().select('-password'); // Exclude passwords
  res.json(users);
});

// View user details
app.get('/users/:id', verifyToken, async (req, res) => {
  const user = await User.findById(req.params.id).select('-password'); // Exclude password
  if (!user) return res.status(404).send('User not found.');
  res.json(user);
});



// Root route for testing
app.get('/', (req, res) => {
    res.send('welcome user!');
  });
  
  // Start the server
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
  });
  

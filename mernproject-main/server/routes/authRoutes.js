const express = require('express');
const router = express.Router();
const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const authenticateJWT = require('../middleware/auth');

/**
 * @route   POST /api/auth/signup
 * @desc    Register a new user
 * @access  Public
 */
router.post('/signup', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    // Validate input
    if (!name || !email || !password) {
      return res.status(400).json({ message: 'Please provide name, email and password' });
    }

    if (password.length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters long' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already exists' });
    }

    // Create new user - using User model's pre-save hook for password hashing
    const user = new User({
      name,
      email: email.toLowerCase(),
      password, // Will be hashed by the pre-save hook in the User model
      role: ['admin', 'user'].includes(role) ? role : 'user'
    });

    await user.save();

    // Generate JWT token
    // Generate JWT token with consistent payload
    const token = jwt.sign(
      { userId: user._id.toString(), email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );

    // Return success response
    res.status(201).json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ message: 'Server error during signup', error: err.message });
  }
});

/**
 * @route   POST /api/auth/login
 * @desc    Authenticate user & get token
 * @access  Public
 */
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({ message: 'Please provide email and password' });
    }

    // Find user by email
    console.log('Login attempt for email:', email.toLowerCase());
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      console.log('User not found with email:', email.toLowerCase());
      // Use generic message for security
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Validate password
    console.log('User found, comparing passwords');
    const isPasswordValid = await bcrypt.compare(password, user.password);
    console.log('Password valid:', isPasswordValid);
    if (!isPasswordValid) {
      // Use generic message for security
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Generate JWT token
    // Generate JWT token with consistent payload
    const token = jwt.sign(
      { userId: user._id.toString(), email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );

    // Return success response
    res.status(200).json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Server error during login', error: err.message });
  }
});

/**
 * @route   GET /api/auth/me
 * @desc    Get current user's profile
 * @access  Private
 */
/**
 * @route   GET /api/auth/me
 * @desc    Get current user's profile
 * @access  Private
 */
router.get('/me', authenticateJWT, async (req, res) => {
  try {
    // Use userId from token payload
    const user = await User.findById(req.user.userId).select('-password');
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    res.status(200).json({
      success: true,
      user
    });
  } catch (err) {
    console.error('Get user profile error:', err);
    res.status(500).json({ message: 'Error fetching user data', error: err.message });
  }
});

/**
 * @route   POST /api/auth/logout
 * @desc    Logout user (client-side only)
 * @access  Public
 */
router.post('/logout', (req, res) => {
  // JWT cannot be invalidated without a token store
  // This endpoint exists for clarity but the actual logout
  // happens on client-side by removing the token from localStorage
  res.status(200).json({ success: true, message: 'Logout successful' });
});

module.exports = router;
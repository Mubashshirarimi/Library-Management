// Import dependencies
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const bookRoutes = require('./routes/bookRoutes');
const authRoutes = require('./routes/authRoutes');
const borrowRoutes = require('./routes/borrowRoutes');
const reviewRoutes = require('./routes/reviewRoutes');

// Initialize express app
const app = express();
const PORT = process.env.PORT || 5000;

// Logging startup information
console.log('Server starting...');
console.log('MONGO_URI:', process.env.MONGO_URI);

// Configure middleware
app.use(cors({
  origin: ['http://localhost:3000', 'http://localhost:3001', 'http://localhost:5000'],  // Frontend origins
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve test HTML file
app.get('/test', (req, res) => {
  res.sendFile(path.join(__dirname, '../client/authTest.html'));
});

// Debug configuration for development
mongoose.set('debug', process.env.NODE_ENV !== 'production');

// MongoDB connection with error handling
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB connected successfully!'))
  .catch((err) => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1); // Exit if we can't connect to the database
  });

// API routes
app.use('/api/books', bookRoutes);
app.use('/api/auth', authRoutes);
app.use('/api/borrows', borrowRoutes);
app.use('/api/reviews', reviewRoutes);

// Root route
app.get('/', (req, res) => {
  res.json({ 
    message: 'Library API is working!',
    version: '1.0.0',
    endpoints: {
      auth: '/api/auth',
      books: '/api/books',
      borrows: '/api/borrows'
    }
  });
});

// Test authentication route
app.get('/api/auth/test', (req, res) => {
  const authHeader = req.headers.authorization;
  console.log('Auth Test - Authorization header:', authHeader);
  
  if (!authHeader) {
    return res.status(401).json({ message: 'No authorization header provided' });
  }
  
  try {
    const token = authHeader.split(' ')[1];
    console.log('Auth Test - Token extracted:', token ? token.substring(0, 15) + '...' : 'none');
    
    if (!token) {
      return res.status(401).json({ message: 'No token provided in authorization header' });
    }
    
    const decoded = require('jsonwebtoken').verify(token, process.env.JWT_SECRET);
    console.log('Auth Test - Token decoded successfully:', decoded);
    
    return res.status(200).json({ 
      message: 'Authentication successful',
      user: decoded
    });
  } catch (error) {
    console.error('Auth Test - JWT verification error:', error);
    return res.status(401).json({ message: 'Invalid token: ' + error.message });
  }
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// 404 handler for undefined routes
app.use('*', (req, res) => {
  res.status(404).json({ message: 'Route not found' });
});

// Start the server
app.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════════╗
║ 🚀 Server running on port ${PORT}              ║
║ API: http://localhost:${PORT}                  ║
║ Environment: ${process.env.NODE_ENV || 'development'}                   ║
╚════════════════════════════════════════════╝
  `);
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  process.exit(1);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
  console.error('Unhandled Promise Rejection:', err);
  process.exit(1);
});
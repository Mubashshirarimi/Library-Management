const jwt = require('jsonwebtoken');

/**
 * Consolidated authentication middleware
 * Verifies JWT tokens and adds user information to the request
 */
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader) {
    console.log('Access denied: No authorization header');
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }

  try {
    const token = authHeader.split(' ')[1];
    if (!token) {
      console.log('Access denied: Invalid token format');
      return res.status(401).json({ message: 'Invalid token format.' });
    }
    
    // Check if JWT_SECRET is available
    if (!process.env.JWT_SECRET) {
      console.error('JWT_SECRET is undefined or empty');
      return res.status(500).json({ message: 'Server configuration error: JWT_SECRET is missing' });
    }
    
    console.log(`Verifying token with secret: ${process.env.JWT_SECRET.substring(0, 3)}...`);
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log('Token successfully decoded:', decoded);
    
    // Ensure we have userId in the expected format
    if (!decoded.userId) {
      console.log('Invalid token payload: Missing userId');
      return res.status(401).json({ message: 'Invalid token payload. Missing userId.' });
    }
    
    req.user = decoded;
    next();
  } catch (err) {
    console.error('JWT verification error:', err);
    // Provide more specific error messages
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Token expired. Please log in again.' });
    } else if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({ message: `JWT error: ${err.message}` });
    } else {
      return res.status(401).json({ message: `Invalid token: ${err.message}` });
    }
  }
};

module.exports = authenticateJWT;

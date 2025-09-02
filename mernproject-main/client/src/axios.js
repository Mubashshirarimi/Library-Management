import axios from 'axios';
import { decodeToken } from './utils/jwt';

/**
 * Custom axios instance configured for API communication
 * - Uses the proxy defined in package.json for local development
 * - Attaches authentication token to all requests
 * - Provides error handling for common API issues
 */
const instance = axios.create({
  baseURL: '/api',
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 10000, // 10 second timeout
});

// Request interceptor - adds auth token to requests
instance.interceptors.request.use(
  (config) => {
    // Get token from localStorage
    const token = localStorage.getItem('token');
    
    // If token exists, add to Authorization header
      if (token) {
        try {
          // Verify token format before using it
          const decoded = decodeToken(token);

          // If decode failed, just skip attaching Authorization (let server validate)
          if (!decoded) {
            console.warn('Token decode returned null - not attaching Authorization header');
          } else {
            // Check expiration safely
            const currentTime = Date.now() / 1000;
            if (decoded.exp && decoded.exp < currentTime) {
              console.warn('Token expired, removing from localStorage');
              localStorage.removeItem('token');
              // Don't add the expired token to headers
            } else {
              // Token is valid, add to headers
              config.headers['Authorization'] = `Bearer ${token}`;
              console.log('Auth header set with valid token');
            }
          }
        } catch (error) {
          console.error('Invalid token format (exception), removing from localStorage:', error);
          localStorage.removeItem('token');
        }
      } else {
      if (process.env.NODE_ENV === 'development') {
        console.log('No auth token available for request');
      }
    }
    
    // Log outgoing requests in development
    if (process.env.NODE_ENV === 'development') {
      console.log(`🚀 API Request: ${config.method?.toUpperCase()} ${config.baseURL}${config.url}`);
    }
    
    return config;
  },
  (error) => {
    // Log request errors
    console.error('❌ Request Error:', error);
    return Promise.reject(error);
  }
);

// Response interceptor - handles response formatting and errors
instance.interceptors.response.use(
  (response) => {
    // Log successful responses in development
    if (process.env.NODE_ENV === 'development') {
      console.log(`✅ API Response: ${response.config.url}`, response.status);
    }
    return response;
  },
  (error) => {
    // Handle authentication errors (401 Unauthorized or 403 Forbidden)
    if (error.response?.status === 401 || error.response?.status === 403) {
      console.warn(`🔒 Authentication failed (${error.response.status}): ${error.response?.data?.message}`);
      
      // Get the error message
      const errorMsg = error.response?.data?.message || '';
      
      // Check for token-related issues
      const isTokenIssue = 
        errorMsg.includes('token') || 
        errorMsg.includes('Token') ||
        errorMsg.includes('Invalid') ||
        errorMsg.includes('expired') ||
        errorMsg.includes('Access denied');
      
      // Don't redirect or clear token if this is a login request
      const isLoginRequest = error.config.url.includes('/auth/login');
      
      if (isTokenIssue && !isLoginRequest) {
        console.warn('Clearing token due to authentication issue');
        localStorage.removeItem('token');
        
        // Redirect to login only if we're not already there
        if (window.location.pathname !== '/login') {
          console.log('Redirecting to login page...');
          window.location.href = '/login';
        }
      }
    }
    
    // Handle server errors
    if (error.response?.status >= 500) {
      console.error('🔥 Server Error:', error.response?.data?.message || 'Unknown server error');
    }
    
    // Log all response errors in development
    if (process.env.NODE_ENV === 'development') {
      console.error(
        `❌ API Error: ${error.config?.method?.toUpperCase()} ${error.config?.url}`,
        error.response?.status,
        error.response?.data
      );
    }
    
    return Promise.reject(error);
  }
);

export default instance;

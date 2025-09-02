import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';

// Page components
import Home from './pages/Home';
import Login from './pages/Login';
import Signup from './pages/Signup';
import BookCatalog from './pages/BookCatalog';
import BookDetails from './pages/BookDetails';
import AdminPanel from './pages/AdminPanel';
import UserDashboard from './pages/UserDashboard';

// Utility components
import { decodeToken } from './utils/jwt';
import LoadingPage from './components/LoadingPage';

// Custom route guard component for protected routes
const ProtectedRoute = ({ children, redirectPath = '/login', isAllowed }) => {
  return isAllowed ? children : <Navigate to={redirectPath} replace />;
};

function App() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [authChecked, setAuthChecked] = useState(false);

  useEffect(() => {
    // Check for authentication on app load
    const validateAuth = () => {
      console.log('Validating authentication...');
      const token = localStorage.getItem('token');
      if (!token) {
        console.log('No token found');
        setLoading(false);
        setAuthChecked(true);
        return;
      }

      try {
  console.log('Decoding token...');
  const decoded = decodeToken(token);
        console.log('Token decoded:', decoded);
        
        // Check if token has required fields
        if (!decoded.userId) {
          console.error('Token missing userId');
          localStorage.removeItem('token');
          setUser(null);
          return;
        }
        
        // Check if token is expired
        const currentTime = Date.now() / 1000;
        if (decoded.exp && decoded.exp < currentTime) {
          console.log('Token expired');
          localStorage.removeItem('token');
          setUser(null);
        } else {
          console.log('Token valid, user authenticated');
          setUser(decoded);
        }
      } catch (error) {
        console.error('Token validation failed:', error);
        localStorage.removeItem('token');
      } finally {
        setLoading(false);
        setAuthChecked(true);
      }
    };

    validateAuth();
  }, []);

  // Display loading state while checking authentication
  if (loading) return <LoadingPage message="Loading application" />;

  return (
    <Router>
      <Routes>
        {/* Only login/signup are available when not authenticated */}
        <Route path="/login" element={user ? <Navigate to="/" replace /> : <Login setUser={setUser} />} />
        <Route path="/signup" element={user ? <Navigate to="/" replace /> : <Signup setUser={setUser} />} />

        {user ? (
          // Authenticated routes
          <>
            <Route path="/" element={<Home user={user} setUser={setUser} />} />
            <Route path="/catalog" element={<BookCatalog user={user} setUser={setUser} />} />
            <Route path="/books/:id" element={<BookDetails user={user} setUser={setUser} />} />

            <Route
              path="/admin"
              element={
                <ProtectedRoute isAllowed={user && user.role === 'admin'} redirectPath="/">
                  <AdminPanel user={user} />
                </ProtectedRoute>
              }
            />
            <Route
              path="/admin/:id"
              element={
                <ProtectedRoute isAllowed={user && user.role === 'admin'} redirectPath="/">
                  <AdminPanel user={user} />
                </ProtectedRoute>
              }
            />

            <Route
              path="/dashboard"
              element={
                <ProtectedRoute isAllowed={!!user} redirectPath="/login">
                  <UserDashboard user={user} />
                </ProtectedRoute>
              }
            />

            <Route path="*" element={<Navigate to="/" replace />} />
          </>
        ) : (
          // If not authenticated, redirect any other route to /login
          <Route path="*" element={<Navigate to="/login" replace />} />
        )}
      </Routes>
    </Router>
  );
}

export default App;

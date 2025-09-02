import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import axios from '../axios';
import { decodeToken } from '../utils/jwt';
import '../styles/LoginPage.css';
import LoadingPage from '../components/LoadingPage';

const Login = ({ setUser }) => {
  const [credentials, setCredentials] = useState({ email: '', password: '' });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleChange = (e) => {
    const { name, value } = e.target;
    setCredentials((prev) => ({ ...prev, [name]: value }));
    if (error) setError('');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!credentials.email || !credentials.password) {
      setError('Please provide both email and password');
      return;
    }

    setLoading(true);
    try {
      const response = await axios.post('/auth/login', credentials);
      const { token } = response.data;
      if (!token) {
        setError('Server error: No authentication token received');
        setLoading(false);
        return;
      }
      localStorage.setItem('token', token);
      const decoded = decodeToken(token);
      if (decoded && setUser) setUser(decoded);
      navigate('/', { replace: true });
    } catch (err) {
      setError(err.response?.data?.message || 'Login failed. Please check your credentials.');
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <LoadingPage message="Signing in" />;

  return (
    <div className="login-container">
      <form onSubmit={handleSubmit}>
        <h2>Sign in to your account</h2>
        {error && <div className="error-message">{error}</div>}
        <input
          type="email"
          name="email"
          placeholder="Email Address"
          value={credentials.email}
          onChange={handleChange}
          required
        />
        <input
          type="password"
          name="password"
          placeholder="Password"
          value={credentials.password}
          onChange={handleChange}
          required
        />
        <button type="submit" disabled={loading}>
          Sign in
        </button>
  {/* Forgot password removed per UX request */}
        <div style={{ marginTop: '20px', textAlign: 'center' }}>
          Don't have an account?{' '}
          <Link to="/signup" style={{ color: '#7b2550' }}>
            Sign up
          </Link>
          <br />
          <Link to="/" style={{ color: '#6b2533', fontSize: '14px', marginTop: '10px', display: 'inline-block' }}>
            ← Back to home
          </Link>
        </div>
      </form>
    </div>
  );
};

export default Login;

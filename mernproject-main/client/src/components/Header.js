import React, { useState, useEffect } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import '../styles/Header.css';
import LogoutButton from './LogoutButton';

const Header = ({ user, setUser }) => {
  const [menuOpen, setMenuOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();

  // Add scroll effect
  useEffect(() => {
    const handleScroll = () => {
      if (window.scrollY > 20) {
        setScrolled(true);
      } else {
        setScrolled(false);
      }
    };

    window.addEventListener('scroll', handleScroll);
    
    return () => {
      window.removeEventListener('scroll', handleScroll);
    };
  }, []);

  const toggleMenu = () => {
    setMenuOpen(!menuOpen);
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
  if (setUser) setUser(null);
  navigate('/login');
  };

  return (
    <header className={`header ${scrolled ? 'scrolled' : ''}`}>
      <div className="header-container">
        <div className="logo">
          <Link to="/">
            <span className="logo-text">Library Management</span>
            <span className="logo-icon">📚</span>
          </Link>
        </div>

        <div className="mobile-toggle" onClick={toggleMenu}>
          <span></span>
          <span></span>
          <span></span>
        </div>

        <nav className={`nav-menu ${menuOpen ? 'active' : ''}`}>
          <ul>
            <li className={location.pathname === '/' ? 'active' : ''}>
              <Link to="/" onClick={() => setMenuOpen(false)}>Home</Link>
            </li>
            <li className={location.pathname === '/catalog' ? 'active' : ''}>
              <Link to="/catalog" onClick={() => setMenuOpen(false)}>Book Catalog</Link>
            </li>
            {user && (
              <li className={location.pathname === '/dashboard' ? 'active' : ''}>
                <Link to="/dashboard" onClick={() => setMenuOpen(false)}>Dashboard</Link>
              </li>
            )}
            {user?.role === 'admin' && (
              <li className={location.pathname.startsWith('/admin') ? 'active' : ''}>
                <Link to="/admin" onClick={() => setMenuOpen(false)}>
                  <span className="admin-icon">⚙️</span> Admin
                </Link>
              </li>
            )}
            <li className="user-menu-item">
              {user ? (
                <div className="user-info">
                  <span className="welcome-text">Hi, <span className="user-name">{user.name || user.email.split('@')[0]}</span></span>
                  <LogoutButton setUser={setUser} className="logout-btn" />
                </div>
              ) : (
                <div className="auth-buttons">
                  <Link to="/login" className="login-btn" onClick={() => setMenuOpen(false)}>Login</Link>
                  <Link to="/signup" className="signup-btn" onClick={() => setMenuOpen(false)}>Sign Up</Link>
                </div>
              )}
            </li>
          </ul>
        </nav>
      </div>
    </header>
  );
};

export default Header;

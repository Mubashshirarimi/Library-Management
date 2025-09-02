import React from 'react';
import { useNavigate } from 'react-router-dom';

const LogoutButton = ({ setUser, className = '' }) => {
  const navigate = useNavigate();

  const handleLogout = () => {
    localStorage.removeItem('token'); // Remove JWT
    if (setUser) setUser(null);
    // force a reload to ensure all components reset
    navigate('/login');
    window.location.reload();
  };

  return (
    <button onClick={handleLogout} className={className || 'logout-btn'}>
      Logout
    </button>
  );
};

export default LogoutButton;

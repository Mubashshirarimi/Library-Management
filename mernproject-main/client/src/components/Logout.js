import React from 'react';
import { useNavigate } from 'react-router-dom';

const Logout = () => {
  const navigate = useNavigate();

  const handleLogout = () => {
    localStorage.removeItem('token'); // Remove the JWT token from localStorage
    navigate('/');  // Redirect to home page
  };

  return (
    <button
      onClick={handleLogout}
      className="absolute top-4 right-4 bg-red-600 text-white py-2 px-4 rounded"
    >
      Logout
    </button>
  );
};

export default Logout;

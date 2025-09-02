import React from 'react';
import '../styles/LoadingPage.css';

const LoadingPage = ({ message = 'Loading' }) => {
  return (
    <div className="loading-page">
      <div className="loading-card">
        <div className="spinner" />
        <h2 className="loading-message">{message}...</h2>
      </div>
    </div>
  );
};

export default LoadingPage;

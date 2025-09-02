import React from 'react';
import ReactDOM from 'react-dom/client'; // Changed from 'react-dom' to 'react-dom/client'
import './index.css';
import App from './App';

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);

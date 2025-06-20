import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import { GlobalProvider } from './contexts/globalContext';
import { ThemeProvider } from './theme/ThemeProvider';
import './index.css';

// Get the root element where the app will be mounted
const container = document.getElementById('root');

if (container) {
  const root = createRoot(container);
  root.render(
    <React.StrictMode>
      <ThemeProvider>
        <GlobalProvider>
          <App />
        </GlobalProvider>
      </ThemeProvider>
    </React.StrictMode>
  );
}

// Handle keyboard shortcuts
window.addEventListener('keydown', (e) => {
  // Prevent default behavior for F5 and Ctrl+R
  if (e.key === 'F5' || (e.ctrlKey && e.key === 'r')) {
    e.preventDefault();
  }
});

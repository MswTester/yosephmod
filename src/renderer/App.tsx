import React from 'react';
import { useGlobal } from './contexts/globalContext';
import Console from './components/console';

const App: React.FC = () => {
  const { state, getState } = useGlobal();

  return (
    <main></main>
  );
};

export default App;
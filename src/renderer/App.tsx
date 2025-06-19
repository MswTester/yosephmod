import React from 'react';
import { useGlobal } from './contexts/globalContext';

const App: React.FC = () => {

  const { state } = useGlobal();

  return (
    <main>
      <pre>{JSON.stringify(state, null, 2)}</pre>
    </main>
  );
};

export default App;
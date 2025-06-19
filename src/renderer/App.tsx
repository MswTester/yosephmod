import React from 'react';
import { useGlobal } from './contexts/globalContext';

const App: React.FC = () => {

  const { globalState } = useGlobal();

  return (
    <main>
      <pre>{JSON.stringify(globalState, null, 2)}</pre>
    </main>
  );
};

export default App;
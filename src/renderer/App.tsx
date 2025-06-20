import React from 'react';
import { useGlobal } from './contexts/globalContext';

const App: React.FC = () => {

  const { state, getState } = useGlobal();

  return (
    <main>
      {Array.from(state.keys()).map((key, i) => (
        <div key={i}>{key}: {JSON.stringify(getState(key))}</div>
      ))}
    </main>
  );
};

export default App;
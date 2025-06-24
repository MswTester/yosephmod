import React, { useState } from 'react';
import Console from './components/console';
import Main from './Main';
import Config from './Config';
import {
  Container,
  Row,
  Col,
  Button,
} from './components/ui/primitive';

type Tab = "main" | "config" | "console"

const App: React.FC = () => {
  const [tab, setTab] = useState<Tab>("main");

  return (
    <Container h="100vh" justify='space-between'>
      <Col justify='center' items='center' h="calc(100% - 2.3rem)" overflowY='auto'>
        {tab === "main" && <Main />}
        {tab === "config" && <Config />}
        {tab === "console" && <Console />}
      </Col>
      <Row justify='center' items='center'>
        {["main", "config", "console"].map((tabName) => (
          <Button
            key={tabName}
            variant={tab === tabName ? "default" : "outline"}
            radius="0"
            w="100%"
            onClick={() => setTab(tabName as Tab)}
          >
            {tabName}
          </Button>
        ))}
      </Row>
    </Container>
  );
};

export default App;
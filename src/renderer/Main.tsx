// Example Codes - 기본 치트 기능들의 예제 코드
import React, { useState, useEffect } from 'react';
import { useGlobal } from './contexts/globalContext';
import {
    Container,
    Row,
    Col,
    Button,
    Input,
    Text,
    Heading,
    Switch,
    Slider
} from './components/ui/primitive';

const Main = () => {
    const { state } = useGlobal();
    return (
        <Container h="100%" p=".5rem" gap=".5rem">
            
        </Container>
    );
};

export default Main;
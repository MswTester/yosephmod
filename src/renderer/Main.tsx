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
    Slider,
    Keybind
} from './components/ui/primitive';
import { DOMtoGK } from './util';

const Main = () => {
    const { state, getState, setState, emit, exec, send, useOn, keymap } = useGlobal();

    // From Process
    // useOn("custom-event", (customArgs) => void);

    // To Process
    // emit("custom-event", customArgs);

    // To Agent
    // send("custom-event", customArgs);

    // On State Changed
    // useEffect(() => void, [state]);

    // Change State
    // setState('key', 'value');

    // Get State
    // getState('key');

    return (
        <Container h="100%" p=".5rem" gap=".5rem">

        </Container>
    );
};

export default Main;
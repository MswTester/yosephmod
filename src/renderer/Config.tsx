// Example Codes - 설정 화면 예제 코드
import React, { useState, useEffect } from 'react';
import { useGlobal } from './contexts/globalContext';
import { 
    Col, 
    CollapsibleIcon, 
    Container, 
    Heading, 
    Input, 
    Row, 
    Switch, 
    Text, 
    Button,
    Slider,
    Select
} from './components/ui/primitive';

const Section = (props: { title: string, children: React.ReactNode }) => {
    const [isOpen, setIsOpen] = useState(false);
    return <Col gap='.5rem'>
        <Row onClick={() => setIsOpen(!isOpen)} gap='.4rem' items='center' cursor='pointer'>
            <CollapsibleIcon isOpen={isOpen} />
            <Heading size="md">
                {props.title}
            </Heading>
        </Row>
        {isOpen && props.children}
    </Col>
}

const Config = () => {
    const { state } = useGlobal();

    return (
        <Container h="100%" p='.5rem' gap='.5rem'>
            
        </Container>
    );
};

export default Config;
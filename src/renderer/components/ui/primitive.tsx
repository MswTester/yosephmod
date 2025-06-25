import React, { useEffect, useState } from "react";
import styled, { css } from "styled-components";
import { DOMtoGK } from "../../util";

// Base Container Component
const Container = styled.div<{
    w?: string;
    h?: string;
    direction?: 'row' | 'column';
    justify?: 'start' | 'center' | 'end' | 'space-between' | 'space-around' | 'space-evenly';
    items?: 'start' | 'center' | 'end' | 'stretch' | 'baseline';
    gap?: string;
    p?: string;
    m?: string;
    bg?: string;
    border?: string;
    radius?: string;
    shadow?: boolean;
    cursor?: string;
    overflow?: 'visible' | 'hidden' | 'scroll' | 'auto';
    overflowX?: 'visible' | 'hidden' | 'scroll' | 'auto';
    overflowY?: 'visible' | 'hidden' | 'scroll' | 'auto';
}>`
    display: flex;
    width: ${props => props.w || '100%'};
    height: ${props => props.h || 'auto'};
    flex-direction: ${props => props.direction || 'column'};
    gap: ${props => props.gap || '0'};
    padding: ${props => props.p || '0'};
    margin: ${props => props.m || '0'};
    background-color: ${props => props.bg || 'transparent'};
    border: ${props => props.border || 'none'};
    border-radius: ${props => props.radius || '0'};
    overflow: ${props => props.overflow || 'visible'};
    overflow-x: ${props => props.overflowX || props.overflow || 'visible'};
    overflow-y: ${props => props.overflowY || props.overflow || 'visible'};
    justify-content: ${props => props.justify || 'start'};
    align-items: ${props => props.items || 'start'};
    cursor: ${props => props.cursor || 'auto'};
    ${props => props.shadow && css`
        box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06);
    `}
`;

const Row = styled(Container)`
    flex-direction: row;
`;

const Col = styled(Container)`
    flex-direction: column;
`;

// Button Variants
const Button = styled.button<{
    variant?: 'default' | 'secondary' | 'outline' | 'ghost' | 'destructive';
    size?: 'sm' | 'md' | 'lg';
    w?: string;
    h?: string;
    radius?: string;
    disabled?: boolean;
}>`
    display: inline-flex;
    align-items: center;
    justify-content: center;
    border-radius: ${props => props.radius || '6px'};
    font-weight: 500;
    transition: all 0.2s ease-in-out;
    cursor: pointer;
    border: none;
    outline: none;
    
    width: ${props => props.w || 'auto'};
    height: ${props => props.h || 'auto'};
    
    ${props => {
        switch (props.size) {
            case 'sm':
                return css`
                    height: 32px;
                    padding: 0 ${props.theme.spacing.md};
                    font-size: ${props.theme.fontSize.sm};
                `;
            case 'lg':
                return css`
                    height: 44px;
                    padding: 0 ${props.theme.spacing.xl};
                    font-size: ${props.theme.fontSize.lg};
                `;
            default:
                return css`
                    height: 36px;
                    padding: 0 ${props.theme.spacing.lg};
                    font-size: ${props.theme.fontSize.md};
                `;
        }
    }}
    
    ${props => {
        switch (props.variant) {
            case 'secondary':
                return css`
                    background-color: ${props.theme.colors.secondary};
                    color: white;
                    &:hover:not(:disabled) {
                        opacity: 0.9;
                    }
                `;
            case 'outline':
                return css`
                    background-color: transparent;
                    color: ${props.theme.colors.text};
                    border: 1px solid ${props.theme.colors.border};
                    &:hover:not(:disabled) {
                        background-color: ${props.theme.colors.background};
                        border-color: ${props.theme.colors.borderFocus};
                    }
                `;
            case 'ghost':
                return css`
                    background-color: transparent;
                    color: ${props.theme.colors.text};
                    &:hover:not(:disabled) {
                        background-color: ${props.theme.colors.background};
                    }
                `;
            case 'destructive':
                return css`
                    background-color: #ef4444;
                    color: white;
                    &:hover:not(:disabled) {
                        background-color: #dc2626;
                    }
                `;
            default:
                return css`
                    background-color: ${props.theme.colors.primary};
                    color: white;
                    &:hover:not(:disabled) {
                        opacity: 0.9;
                    }
                `;
        }
    }}
    
    &:disabled {
        opacity: 0.5;
        cursor: not-allowed;
    }
    
    &:focus-visible {
        ring: 2px solid ${props => props.theme.colors.borderFocus};
        ring-offset: 2px;
    }
`;

// Input Component
const Input = styled.input<{
    variant?: 'default' | 'filled';
    error?: boolean;
    family?: 'mono' | 'sans' | 'serif';
    mw?: string;
    align?: 'left' | 'center' | 'right';
}>`
    display: flex;
    height: 36px;
    width: 100%;
    border-radius: 6px;
    border: 1px solid ${props => props.error ? '#ef4444' : props.theme.colors.border};
    background-color: ${props => props.variant === 'filled' ? props.theme.colors.background : 'transparent'};
    padding: 0 ${props => props.theme.spacing.md};
    font-size: ${props => props.theme.fontSize.sm};
    color: ${props => props.theme.colors.text};
    transition: all 0.2s ease-in-out;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-family: ${props => props.family || 'sans'};
    max-width: ${props => props.mw || '100%'};
    text-align: ${props => props.align || 'left'};
    
    &::placeholder {
        color: ${props => props.theme.colors.textMuted};
    }
    
    &:focus {
        outline: none;
        border-color: ${props => props.theme.colors.borderFocus};
        ring: 2px solid ${props => props.theme.colors.borderFocus};
        ring-opacity: 0.2;
    }
    
    &:disabled {
        cursor: not-allowed;
        opacity: 0.5;
    }
`;

// Keybind Component
const Keybind = (props: {
    onKeyChange?: (key: string) => void;
    mw?: string;
} & React.InputHTMLAttributes<HTMLInputElement>) => {
    return <Input align="center" mw={props.mw} onKeyDown={(e) => {e.preventDefault(); props.onKeyChange?.(DOMtoGK(e.code))}} {...props} />
}

// Label Component
const Label = styled.label<{
    size?: 'sm' | 'md' | 'lg';
    required?: boolean;
}>`
    font-size: ${props => {
        switch (props.size) {
            case 'sm': return props.theme.fontSize.sm;
            case 'lg': return props.theme.fontSize.lg;
            default: return props.theme.fontSize.md;
        }
    }};
    font-weight: 500;
    color: ${props => props.theme.colors.text};
    
    ${props => props.required && css`
        &::after {
            content: " *";
            color: #ef4444;
        }
    `}
`;

// Typography
const Heading = styled.h1<{
    size?: 'sm' | 'md' | 'lg' | 'xl' | '2xl' | '3xl';
    weight?: 'normal' | 'medium' | 'semibold' | 'bold';
    align?: 'left' | 'center' | 'right';
    truncate?: boolean;
}>`
    font-size: ${props => {
        switch (props.size) {
            case 'sm': return props.theme.fontSize.lg;
            case 'md': return props.theme.fontSize.xl;
            case 'lg': return props.theme.fontSize['2xl'];
            case 'xl': return props.theme.fontSize['3xl'];
            case '2xl': return props.theme.fontSize['4xl'];
            case '3xl': return props.theme.fontSize['5xl'];
            default: return props.theme.fontSize['2xl'];
        }
    }};
    font-weight: ${props => {
        switch (props.weight) {
            case 'normal': return 400;
            case 'medium': return 500;
            case 'semibold': return 600;
            case 'bold': return 700;
            default: return 600;
        }
    }};
    color: ${props => props.theme.colors.text};
    margin: 0;
    line-height: 1.2;
    text-align: ${props => props.align || 'left'};
    
    ${props => props.truncate && css`
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    `}
`;

const Text = styled.p<{
    w?: string;
    size?: 'xs' | 'sm' | 'md' | 'lg';
    muted?: boolean;
    weight?: 'normal' | 'medium' | 'semibold';
    align?: 'left' | 'center' | 'right';
    truncate?: boolean;
    clamp?: number;
    family?: 'mono' | 'sans' | 'serif';
}>`
    font-size: ${props => {
        switch (props.size) {
            case 'xs': return props.theme.fontSize.xs;
            case 'sm': return props.theme.fontSize.sm;
            case 'lg': return props.theme.fontSize.lg;
            default: return props.theme.fontSize.md;
        }
    }};
    font-weight: ${props => {
        switch (props.weight) {
            case 'medium': return 500;
            case 'semibold': return 600;
            default: return 400;
        }
    }};
    color: ${props => props.muted ? props.theme.colors.textMuted : props.theme.colors.text};
    margin: 0;
    line-height: 1.5;
    text-align: ${props => props.align || 'left'};
    font-family: ${props => props.family || 'sans'};
        
    ${props => props.truncate && css`
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    `}
    ${props => props.w && css`
        width: ${props.w};
    `}
    ${props => props.clamp && css`
        display: -webkit-box;
        -webkit-line-clamp: ${props.clamp};
        -webkit-box-orient: vertical;
        overflow: hidden;
        text-overflow: ellipsis;
    `}
`;

// Badge Component
const Badge = styled.span<{
    variant?: 'default' | 'secondary' | 'outline' | 'destructive';
}>`
    display: inline-flex;
    align-items: center;
    border-radius: 4px;
    padding: 2px ${props => props.theme.spacing.sm};
    font-size: ${props => props.theme.fontSize.xs};
    font-weight: 500;
    line-height: 1;
    
    ${props => {
        switch (props.variant) {
            case 'secondary':
                return css`
                    background-color: ${props.theme.colors.secondary};
                    color: white;
                `;
            case 'outline':
                return css`
                    background-color: transparent;
                    color: ${props.theme.colors.text};
                    border: 1px solid ${props.theme.colors.border};
                `;
            case 'destructive':
                return css`
                    background-color: #ef4444;
                    color: white;
                `;
            default:
                return css`
                    background-color: ${props.theme.colors.primary};
                    color: white;
                `;
        }
    }}
`;

// Switch Component (Checkbox-based)
const Switch = styled.input.attrs({ type: 'checkbox' })<{
    checked?: boolean;
    disabled?: boolean;
}>`
    position: relative;
    display: inline-flex;
    width: 44px;
    height: 24px;
    border-radius: 12px;
    border: none;
    cursor: pointer;
    transition: all 0.2s ease-in-out;
    outline: none;
    appearance: none;
    background-color: ${props => props.checked ? props.theme.colors.primary : props.theme.colors.border};
    
    &:disabled {
        opacity: 0.5;
        cursor: not-allowed;
    }
    
    &:focus-visible {
        ring: 2px solid ${props => props.theme.colors.borderFocus};
        ring-offset: 2px;
    }
    
    &::before {
        content: '';
        position: absolute;
        top: 2px;
        left: ${props => props.checked ? '22px' : '2px'};
        width: 20px;
        height: 20px;
        border-radius: 50%;
        background-color: white;
        transition: all 0.2s ease-in-out;
        box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
    }
    
    &:checked {
        background-color: ${props => props.theme.colors.primary};
        
        &::before {
            left: 22px;
        }
    }
`;

// Checkbox Component
const Checkbox = styled.input.attrs({ type: 'checkbox' })<{
    error?: boolean;
}>`
    width: 16px;
    height: 16px;
    border-radius: 4px;
    border: 1px solid ${props => props.error ? '#ef4444' : props.theme.colors.border};
    background-color: ${props => props.checked ? props.theme.colors.primary : 'transparent'};
    cursor: pointer;
    appearance: none;
    transition: all 0.2s ease-in-out;
    
    &:checked {
        background-color: ${props => props.theme.colors.primary};
        border-color: ${props => props.theme.colors.primary};
        background-image: url("data:image/svg+xml,%3csvg viewBox='0 0 16 16' fill='white' xmlns='http://www.w3.org/2000/svg'%3e%3cpath d='m13.854 3.646-7.5 7.5a.5.5 0 0 1-.708 0l-3.5-3.5a.5.5 0 1 1 .708-.708L6 10.293l7.146-7.147a.5.5 0 0 1 .708.708z'/%3e%3c/svg%3e");
        background-size: 12px 12px;
        background-position: center;
        background-repeat: no-repeat;
    }
    
    &:focus {
        outline: none;
        ring: 2px solid ${props => props.theme.colors.borderFocus};
        ring-offset: 2px;
    }
    
    &:disabled {
        opacity: 0.5;
        cursor: not-allowed;
    }
`;

// Select Component
const Select = styled.select<{
    error?: boolean;
    mw?: string;
}>`
    display: flex;
    height: 36px;
    width: 100%;
    border-radius: 6px;
    border: 1px solid ${props => props.error ? '#ef4444' : props.theme.colors.border};
    background-color: transparent;
    padding: 0 ${props => props.theme.spacing.md};
    font-size: ${props => props.theme.fontSize.sm};
    color: ${props => props.theme.colors.text};
    cursor: pointer;
    transition: all 0.2s ease-in-out;
    max-width: ${props => props.mw || '100%'};
    
    &:focus {
        outline: none;
        border-color: ${props => props.theme.colors.borderFocus};
        ring: 2px solid ${props => props.theme.colors.borderFocus};
        ring-opacity: 0.2;
    }
    
    &:disabled {
        cursor: not-allowed;
        opacity: 0.5;
    }
`;

// Textarea Component
const Textarea = styled.textarea<{
    error?: boolean;
    resize?: 'none' | 'vertical' | 'horizontal' | 'both';
}>`
    display: flex;
    min-height: 80px;
    width: 100%;
    border-radius: 6px;
    border: 1px solid ${props => props.error ? '#ef4444' : props.theme.colors.border};
    background-color: transparent;
    padding: ${props => props.theme.spacing.md};
    font-size: ${props => props.theme.fontSize.sm};
    color: ${props => props.theme.colors.text};
    resize: ${props => props.resize || 'vertical'};
    transition: all 0.2s ease-in-out;
    
    &::placeholder {
        color: ${props => props.theme.colors.textMuted};
    }
    
    &:focus {
        outline: none;
        border-color: ${props => props.theme.colors.borderFocus};
        ring: 2px solid ${props => props.theme.colors.borderFocus};
        ring-opacity: 0.2;
    }
    
    &:disabled {
        cursor: not-allowed;
        opacity: 0.5;
    }
`;

// Progress Component
const Progress = styled.div`
    position: relative;
    height: 8px;
    width: 100%;
    overflow: hidden;
    border-radius: 4px;
    background-color: ${props => props.theme.colors.border};
`;

const ProgressBar = styled.div<{
    value: number;
}>`
    height: 100%;
    width: ${props => props.value}%;
    background-color: ${props => props.theme.colors.primary};
    transition: width 0.2s ease-in-out;
`;

// Separator
const Separator = styled.div<{
    orientation?: 'horizontal' | 'vertical';
}>`
    ${props => props.orientation === 'vertical' ? css`
        width: 1px;
        height: 100%;
    ` : css`
        height: 1px;
        width: 100%;
    `}
    background-color: ${props => props.theme.colors.border};
`;

// Slider Component
const SliderContainer = styled.div`
    position: relative;
    width: 100%;
    height: 20px;
    display: flex;
    align-items: center;
`;

const SliderTrack = styled.div`
    position: relative;
    width: 100%;
    height: 4px;
    background-color: ${props => props.theme.colors.border};
    border-radius: 2px;
`;

const SliderRange = styled.div<{
    percentage: number;
}>`
    position: absolute;
    height: 100%;
    width: ${props => props.percentage}%;
    background-color: ${props => props.theme.colors.primary};
    border-radius: 2px;
    transition: all 0.1s ease-in-out;
`;

const SliderThumb = styled.input.attrs({ type: 'range' })<{
    min?: number;
    max?: number;
    step?: number;
    value?: number;
}>`
    position: absolute;
    width: 100%;
    height: 100%;
    opacity: 0;
    cursor: pointer;
    appearance: none;
    background: transparent;
    outline: none;
    
    &::-webkit-slider-thumb {
        appearance: none;
        width: 16px;
        height: 16px;
        border-radius: 50%;
        background-color: ${props => props.theme.colors.primary};
        border: 2px solid white;
        box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1);
        cursor: pointer;
        opacity: 1;
        transition: all 0.1s ease-in-out;
        
        &:hover {
            transform: scale(1.1);
        }
    }
    
    &::-moz-range-thumb {
        width: 16px;
        height: 16px;
        border-radius: 50%;
        background-color: ${props => props.theme.colors.primary};
        border: 2px solid white;
        box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1);
        cursor: pointer;
        transition: all 0.1s ease-in-out;
        
        &:hover {
            transform: scale(1.1);
        }
    }
    
    &:disabled {
        opacity: 0.5;
        cursor: not-allowed;
        
        &::-webkit-slider-thumb {
            cursor: not-allowed;
        }
        
        &::-moz-range-thumb {
            cursor: not-allowed;
        }
    }
`;

const CollapsibleIcon = styled.span<{
    isOpen?: boolean;
}>`
    transform: rotate(${props => props.isOpen ? '90deg' : '0deg'});
    transition: transform 0.2s;
    
    &::before {
        content: '▶';
        font-size: ${props => props.theme.fontSize.sm};
    }
`;

// Slider Wrapper Component
interface SliderProps {
    min?: number;
    max?: number;
    step?: number;
    value?: number;
    onChange?: (value: number) => void;
    disabled?: boolean;
    className?: string;
}

const Slider: React.FC<SliderProps> = ({
    min = 0,
    max = 100,
    step = 1,
    value = 0,
    onChange,
    disabled = false,
    className
}) => {
    const percentage = ((value - min) / (max - min)) * 100;
    
    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const newValue = parseFloat(e.target.value);
        onChange?.(newValue);
    };
    
    return (
        <SliderContainer className={className}>
            <SliderTrack>
                <SliderRange percentage={percentage} />
                <SliderThumb
                    min={min}
                    max={max}
                    step={step}
                    value={value}
                    onChange={handleChange}
                    disabled={disabled}
                />
            </SliderTrack>
        </SliderContainer>
    );
};

export { 
    Container, 
    Row, 
    Col, 
    Button, 
    Input, 
    Keybind, 
    Label,
    Heading,
    Text,
    Badge,
    Switch,
    Checkbox,
    Select,
    Textarea,
    Progress,
    ProgressBar,
    Separator,
    CollapsibleIcon,
    Slider,
    SliderContainer,
    SliderTrack,
    SliderRange,
    SliderThumb
};

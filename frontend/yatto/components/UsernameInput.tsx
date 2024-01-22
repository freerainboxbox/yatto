import React from 'react';

interface UsernameInputProps {
    value: string;
    onChange: (value: string) => void;
}

const UsernameInput: React.FC<UsernameInputProps> = () => {
    return (
        <input
            className = "userpass"
            type="text"
            placeholder="Enter your username"
            style={{ width: '200px', height: '30px' }}
            id = "username"
        />
    );
};

export default UsernameInput;

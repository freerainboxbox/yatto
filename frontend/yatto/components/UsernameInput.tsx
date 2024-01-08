import React from 'react';

const UsernameInput: React.FC = () => {
    return (
        <input
            class = "userpass"
            type="text"
            placeholder="Enter your username"
            style={{ width: '200px', height: '30px' }}
            id = "username"
        />
    );
};

export default UsernameInput;

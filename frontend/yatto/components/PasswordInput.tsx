import React, { useState } from 'react';


const PasswordInput: React.FC = () => {
    const [password, setPassword] = useState('');

    const handlePasswordChange = (event: React.ChangeEvent<HTMLInputElement>) => {
        const input = event.target.value;
        const censoredInput = input.replace(/./g, '*');
        setPassword(censoredInput);
    };

    return (
        <input
            class = "userpass"
            type="password"
            value={password}
            placeholder='Enter your password'
            onChange={handlePasswordChange}
            style={{ width: '200px', height: '30px' }}
            id = "password"
        />
    );
};

export default PasswordInput;

import React, { useState } from "react";
import "./Enums";

import PageTitle from "./PageTitle";

import UsernameInput from "./UsernameInput";
import PasswordInput from "./PasswordInput";
import SubmitFormButton from "./SubmitFormButton";

const UserPassInput: React.FC<UserPassMode> = (mode: UserPassMode) => {
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");

    const handleSubmit = (event: React.FormEvent) => {
        event.preventDefault();
        endpoint = mode === UserPassMode.Login ? "/api/login" : "/api/register";
    };

    return (
        <>
            <PageTitle>{mode === UserPassMode.Login ? "Login" : "Register"}</PageTitle>
            <form onSubmit={handleSubmit}>
                <UsernameInput value={username} onChange={setUsername} />
                <PasswordInput value={password} onChange={setPassword} />
                <SubmitFormButton />
            </form>
        </>
    );
};

export default UserPassInput;

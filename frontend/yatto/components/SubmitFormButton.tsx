import React from 'react';

type SubmitFormButtonProps = {
    formId: string;
    method: string;
    endpoint: string;
};

const SubmitFormButton: React.FC<SubmitFormButtonProps> = ({
    formId,
    method,
    endpoint,
}) => {
    const handleSubmit = (event: React.FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        const form = document.getElementById(formId) as HTMLFormElement;
        form.method = method;
        form.action = endpoint;
        form.submit();
    };

    return (
        <button type="submit" onClick={handleSubmit}>
            Submit
        </button>
    );
};

export default SubmitFormButton;

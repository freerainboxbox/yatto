import React from 'react';

interface PageTitleProps {
    text: string;
}

const PageTitle: React.FC<PageTitleProps> = ({ text }) => {
    return <h1>{text}</h1>;
};

export default PageTitle;

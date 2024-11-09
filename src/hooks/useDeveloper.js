import { useState } from 'react';

const useDeveloper = () => {
    const [user, setUser] = useState(null);

    const loginUser = (userData) => {
        setUser(userData);
    };

    return { user, setUser: loginUser };
};

export default useDeveloper;

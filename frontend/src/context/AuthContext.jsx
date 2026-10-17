import { createContext, useState, useEffect, useContext } from 'react';
import axios from 'axios';

const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  // Page load hone par check karein ki user pehle se logged in hai kya
  useEffect(() => {
    const checkAuth = async () => {
      try {
        const res = await axios.get('/api/auth/me', { withCredentials: true });
        setUser(res.data.user);
      } catch {
        // 401 ka matlab hai user logged in nahi hai — yeh expected hai
        setUser(null);
      } finally {
        setLoading(false);
      }
    };

    checkAuth();
  }, []);

  const login = async (email, password) => {
    const res = await axios.post(
      '/api/auth/login',
      { email, password },
      { withCredentials: true }
    );
    setUser(res.data.user);
    return res.data;
  };

  const register = async (fullNameOrObj, email, password, role, affiliation, researchInterests) => {
    let payload;
    if (typeof fullNameOrObj === 'object' && fullNameOrObj !== null) {
      payload = {
        full_name: fullNameOrObj.full_name || fullNameOrObj.fullName,
        email: fullNameOrObj.email,
        password: fullNameOrObj.password,
        role: fullNameOrObj.role,
        affiliation: fullNameOrObj.affiliation,
        research_interests: fullNameOrObj.research_interests || fullNameOrObj.researchInterests || [],
      };
    } else {
      payload = {
        full_name: fullNameOrObj,
        email,
        password,
        role,
        affiliation,
        research_interests: researchInterests || [],
      };
    }

    const res = await axios.post(
      '/api/auth/register',
      payload,
      { withCredentials: true }
    );
    return res.data;
  };

  const verifyEmail = async (token) => {
    const res = await axios.post(
      '/api/auth/verify-email',
      { token },
      { withCredentials: true }
    );
    return res.data;
  };

  const resendVerification = async (email) => {
    const res = await axios.post(
      '/api/auth/resend-verification',
      { email },
      { withCredentials: true }
    );
    return res.data;
  };

  const getSsoConfig = async () => {
    const res = await axios.get('/api/auth/sso/config', { withCredentials: true });
    return res.data;
  };

  const logout = async () => {
    await axios.post('/api/auth/logout', {}, { withCredentials: true });
    setUser(null);
  };

  const forgotPassword = async (email) => {
    const res = await axios.post(
      '/api/auth/forgot-password',
      { email },
      { withCredentials: true }
    );
    return res.data;
  };

  const resetPassword = async (token, password) => {
    const res = await axios.post(
      '/api/auth/reset-password',
      { token, password },
      { withCredentials: true }
    );
    return res.data;
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        setUser,
        login,
        register,
        verifyEmail,
        resendVerification,
        getSsoConfig,
        logout,
        loading,
        forgotPassword,
        resetPassword,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

// eslint-disable-next-line react-refresh/only-export-components
export const useAuth = () => useContext(AuthContext);
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
      } catch (err) {
        // 401 ka matlab hai user logged in nahi hai — yeh expected hai
        // Console mein error dikhane ki zaroorat nahi
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

  const register = async (full_name, email, password, role) => {
  const res = await axios.post(
    '/api/auth/register',
    { full_name, email, password, role },
    { withCredentials: true }
  );
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
      value={{ user, login, register, logout, loading, forgotPassword, resetPassword }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);
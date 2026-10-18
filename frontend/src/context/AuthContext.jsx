import { createContext, useState, useEffect, useContext, useRef, useCallback } from 'react';
import axios from 'axios';

const AuthContext = createContext();

// FR-04: Inactivity timeout is 30 minutes (1,800,000 ms)
const INACTIVITY_TIMEOUT_MS = 30 * 60 * 1000;
// Warning shows 2 minutes before expiration (28 minutes of inactivity)
const WARNING_THRESHOLD_MS = 28 * 60 * 1000;

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [showIdleWarning, setShowIdleWarning] = useState(false);
  const [secondsRemaining, setSecondsRemaining] = useState(120);

  const lastActivityRef = useRef(Date.now());
  const warningTimerRef = useRef(null);

  // Heartbeat to keep session alive and update activity timestamp
  const heartbeat = useCallback(async () => {
    try {
      lastActivityRef.current = Date.now();
      setShowIdleWarning(false);
      await axios.get('/api/auth/me', { withCredentials: true });
    } catch {
      // 401 will be caught by interceptor
    }
  }, []);

  // Logout handler
  const logout = useCallback(async () => {
    try {
      await axios.post('/api/auth/logout', {}, { withCredentials: true });
    } catch {
      // Ignore network errors during logout
    } finally {
      setUser(null);
      setShowIdleWarning(false);
    }
  }, []);

  // Setup Axios 401 interceptor for automatic session expiration handling
  useEffect(() => {
    const interceptor = axios.interceptors.response.use(
      (response) => response,
      (error) => {
        if (error.response?.status === 401) {
          const code = error.response.data?.code;
          if (code === 'SESSION_IDLE_TIMEOUT' || code === 'SESSION_REVOKED') {
            setUser(null);
            setShowIdleWarning(false);
            if (window.location.pathname !== '/login') {
              const msg = encodeURIComponent(
                code === 'SESSION_IDLE_TIMEOUT'
                  ? 'Your session has expired due to 30 minutes of inactivity. Please log in again.'
                  : 'Your session has been invalidated. Please log in again.'
              );
              window.location.href = `/login?error=session_expired&message=${msg}`;
            }
          }
        }
        return Promise.reject(error);
      }
    );

    return () => {
      axios.interceptors.response.eject(interceptor);
    };
  }, []);

  // Initial authentication check on application mount
  useEffect(() => {
    const checkAuth = async () => {
      try {
        const res = await axios.get('/api/auth/me', { withCredentials: true });
        setUser(res.data.user);
        lastActivityRef.current = Date.now();
      } catch {
        setUser(null);
      } finally {
        setLoading(false);
      }
    };

    checkAuth();
  }, []);

  // FR-04: Client-side idle inactivity tracking
  useEffect(() => {
    if (!user) {
      setShowIdleWarning(false);
      return;
    }

    lastActivityRef.current = Date.now();

    // Event listener to record user activity (throttled to once every 5 seconds)
    let lastRecorded = Date.now();
    const handleUserActivity = () => {
      const now = Date.now();
      if (now - lastRecorded > 5000) {
        lastActivityRef.current = now;
        lastRecorded = now;
        if (showIdleWarning) {
          setShowIdleWarning(false);
        }
      }
    };

    const activityEvents = [
      'mousemove',
      'mousedown',
      'keydown',
      'scroll',
      'touchstart',
      'click',
    ];

    activityEvents.forEach((event) => {
      window.addEventListener(event, handleUserActivity, { passive: true });
    });

    // Interval to check inactivity every 5 seconds
    const intervalId = setInterval(() => {
      const idleTime = Date.now() - lastActivityRef.current;

      if (idleTime >= INACTIVITY_TIMEOUT_MS) {
        // 30 minutes of inactivity exceeded -> Auto logout
        clearInterval(intervalId);
        logout().then(() => {
          const msg = encodeURIComponent(
            'Your session has expired due to 30 minutes of inactivity. Please log in again.'
          );
          window.location.href = `/login?error=session_expired&message=${msg}`;
        });
      } else if (idleTime >= WARNING_THRESHOLD_MS) {
        // 28 minutes of inactivity reached -> Show warning modal
        const remaining = Math.max(
          0,
          Math.ceil((INACTIVITY_TIMEOUT_MS - idleTime) / 1000)
        );
        setSecondsRemaining(remaining);
        setShowIdleWarning(true);
      } else {
        setShowIdleWarning(false);
      }
    }, 5000);

    return () => {
      clearInterval(intervalId);
      if (warningTimerRef.current) clearInterval(warningTimerRef.current);
      activityEvents.forEach((event) => {
        window.removeEventListener(event, handleUserActivity);
      });
    };
  }, [user, logout, showIdleWarning]);

  const login = async (email, password) => {
    const res = await axios.post(
      '/api/auth/login',
      { email, password },
      { withCredentials: true }
    );
    setUser(res.data.user);
    lastActivityRef.current = Date.now();
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

  // RBAC & Permission Helper Functions
  const normalizeClientRole = (role) => {
    if (!role || typeof role !== 'string') return null;
    const clean = role.trim().toUpperCase().replace(/[\s\-]+/g, '_');
    if (clean === 'SYSTEM_ADMIN' || clean === 'SYSTEMADMIN' || clean === 'ADMIN') return 'SYSTEM_ADMIN';
    if (clean === 'RESEARCHER') return 'RESEARCHER';
    if (clean === 'STUDENT') return 'STUDENT';
    return null;
  };

  const hasRole = (...roles) => {
    if (!user?.role) return false;
    const userRole = normalizeClientRole(user.role);
    return roles.flat().some((r) => normalizeClientRole(r) === userRole);
  };

  const isAdmin = hasRole('SYSTEM_ADMIN');
  const isResearcher = hasRole('RESEARCHER');
  const isStudent = hasRole('STUDENT');

  const hasPermission = (permission) => {
    if (isAdmin) return true;
    if (isResearcher) {
      return [
        'papers:read',
        'papers:upload',
        'summaries:generate',
        'collections:create',
        'collections:manage',
      ].includes(permission);
    }
    if (isStudent) {
      return ['papers:read', 'summaries:generate', 'collections:create'].includes(permission);
    }
    return false;
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
        heartbeat,
        hasRole,
        hasPermission,
        isAdmin,
        isResearcher,
        isStudent,
      }}
    >
      {children}

      {/* FR-04: Session Expiration Warning Modal */}
      {showIdleWarning && user && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4 animate-fadeIn">
          <div className="bg-white rounded-2xl p-6 md:p-8 max-w-md w-full shadow-2xl border border-amber-200">
            <div className="flex items-center gap-3 mb-4">
              <span className="text-3xl">⏳</span>
              <div>
                <h3 className="text-xl font-bold text-slate-800">
                  Session Expiring Soon
                </h3>
                <p className="text-sm text-slate-500">Inactivity Warning</p>
              </div>
            </div>

            <p className="text-slate-600 mb-6 text-sm leading-relaxed">
              You have been inactive for over 28 minutes. For your security, your
              session will automatically expire in{' '}
              <strong className="text-amber-600 font-semibold">
                {secondsRemaining}s
              </strong>
              . Would you like to stay signed in?
            </p>

            <div className="flex flex-col sm:flex-row gap-3">
              <button
                onClick={heartbeat}
                className="flex-1 py-2.5 px-4 bg-indigo-600 hover:bg-indigo-700 text-white font-semibold rounded-lg shadow-sm transition duration-200 cursor-pointer"
              >
                Stay Signed In
              </button>
              <button
                onClick={logout}
                className="flex-1 py-2.5 px-4 bg-slate-100 hover:bg-slate-200 text-slate-700 font-medium rounded-lg transition duration-200 cursor-pointer"
              >
                Sign Out
              </button>
            </div>
          </div>
        </div>
      )}
    </AuthContext.Provider>
  );
};

// eslint-disable-next-line react-refresh/only-export-components
export const useAuth = () => useContext(AuthContext);
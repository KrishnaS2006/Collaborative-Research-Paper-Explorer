import { useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function ResetPassword() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get('token') || '';

  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [loading, setLoading] = useState(false);

  const { resetPassword } = useAuth();
  const navigate = useNavigate();

  // Password policy criteria (consistent with Register.jsx and backend)
  const isLengthValid = password.length >= 8;
  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSpecial = /[^A-Za-z0-9\s]/.test(password);
  const isPasswordStrong = isLengthValid && hasUpper && hasLower && hasNumber && hasSpecial;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (!token) {
      setError('Missing or invalid reset token. Please request a new password reset link.');
      return;
    }

    if (!password || !confirmPassword) {
      setError('Please fill in all fields.');
      return;
    }

    if (!isPasswordStrong) {
      setError(
        'Password must be at least 8 characters long and contain uppercase, lowercase, a number, and a special character.'
      );
      return;
    }

    if (password !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }

    setLoading(true);
    try {
      await resetPassword(token, password);
      setSuccess(true);
      setTimeout(() => {
        navigate('/login');
      }, 2500);
    } catch (err) {
      setError(
        err.response?.data?.error ||
          'Failed to reset password. The token may be expired or already used.'
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 to-slate-200 font-sans p-4 py-10">
      <div className="bg-white p-8 md:p-10 rounded-xl shadow-xl w-full max-w-md">
        <h1 className="text-2xl font-bold text-center text-slate-800 mb-2">
          Set New Password
        </h1>
        <p className="text-center text-slate-500 text-sm mb-6">
          Create a strong, new password for your account.
        </p>

        {!token ? (
          <div className="text-center space-y-4">
            <div className="bg-amber-50 border border-amber-200 text-amber-800 p-4 rounded-lg text-sm">
              <span className="font-semibold block mb-1">Invalid or Missing Reset Link</span>
              No password reset token was found in the link. Please request a new password reset link.
            </div>
            <Link
              to="/forgot-password"
              className="inline-block px-4 py-2 bg-indigo-600 text-white rounded-lg font-semibold text-sm hover:bg-indigo-700 transition duration-200"
            >
              Request New Reset Link
            </Link>
          </div>
        ) : success ? (
          <div className="text-center space-y-4">
            <div className="bg-emerald-50 border border-emerald-200 text-emerald-800 p-4 rounded-lg text-sm">
              <div className="text-2xl mb-2">🎉</div>
              <p className="font-semibold mb-1">Password Reset Complete!</p>
              <p>Your password has been updated. Redirecting you to sign in...</p>
            </div>
            <Link
              to="/login"
              className="inline-block px-4 py-2 bg-indigo-600 text-white rounded-lg font-semibold text-sm hover:bg-indigo-700 transition duration-200"
            >
              Sign In Now →
            </Link>
          </div>
        ) : (
          <form onSubmit={handleSubmit}>
            {error && (
              <div className="bg-red-100 border border-red-200 text-red-700 p-3 rounded-lg mb-5 text-sm text-center">
                {error}
              </div>
            )}

            {/* New Password */}
            <div className="mb-4">
              <label className="block mb-2 text-sm font-semibold text-slate-700">
                New Password
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                required
                className="w-full px-4 py-2.5 border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition duration-200"
              />
            </div>

            {/* Confirm New Password */}
            <div className="mb-3">
              <label className="block mb-2 text-sm font-semibold text-slate-700">
                Confirm New Password
              </label>
              <input
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="••••••••"
                required
                className="w-full px-4 py-2.5 border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition duration-200"
              />
            </div>

            {/* Password Policy Guidelines */}
            <div className="mb-5 p-3 bg-slate-50 border border-slate-200 rounded-lg text-xs space-y-1">
              <p className="font-semibold text-slate-700 mb-1">Password requirements:</p>
              <div
                className={`flex items-center gap-1.5 ${
                  isLengthValid ? 'text-emerald-600 font-medium' : 'text-slate-500'
                }`}
              >
                <span>{isLengthValid ? '✓' : '•'}</span>
                <span>At least 8 characters long</span>
              </div>
              <div
                className={`flex items-center gap-1.5 ${
                  hasUpper && hasLower ? 'text-emerald-600 font-medium' : 'text-slate-500'
                }`}
              >
                <span>{hasUpper && hasLower ? '✓' : '•'}</span>
                <span>Both uppercase (A-Z) and lowercase (a-z) letters</span>
              </div>
              <div
                className={`flex items-center gap-1.5 ${
                  hasNumber ? 'text-emerald-600 font-medium' : 'text-slate-500'
                }`}
              >
                <span>{hasNumber ? '✓' : '•'}</span>
                <span>At least one number (0-9)</span>
              </div>
              <div
                className={`flex items-center gap-1.5 ${
                  hasSpecial ? 'text-emerald-600 font-medium' : 'text-slate-500'
                }`}
              >
                <span>{hasSpecial ? '✓' : '•'}</span>
                <span>At least one special character (!@#$%^&*)</span>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 bg-indigo-600 text-white rounded-lg font-semibold hover:bg-indigo-700 transition duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? 'Resetting Password...' : 'Reset Password'}
            </button>

            <p className="text-center mt-6 text-sm text-slate-600">
              <Link to="/login" className="text-indigo-600 font-semibold hover:underline">
                ← Back to Sign In
              </Link>
            </p>
          </form>
        )}
      </div>
    </div>
  );
}

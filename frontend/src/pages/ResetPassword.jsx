import { useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function ResetPassword() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get('token') || '';

  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
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
  const isPasswordStrong =
    isLengthValid && hasUpper && hasLower && hasNumber && hasSpecial;

  const passwordsMatch =
    confirmPassword.length > 0 && password === confirmPassword;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (!token) {
      setError(
        'Missing or invalid reset token. Please request a new password reset link.'
      );
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
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-indigo-50 via-slate-50 to-purple-100 font-sans p-4 py-10">
      {/* Decorative background blobs */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -top-24 -left-24 w-72 h-72 bg-indigo-300 rounded-full mix-blend-multiply filter blur-3xl opacity-30 animate-pulse" />
        <div className="absolute -bottom-24 -right-24 w-72 h-72 bg-purple-300 rounded-full mix-blend-multiply filter blur-3xl opacity-30 animate-pulse" />
      </div>

      <div className="relative bg-white/90 backdrop-blur-sm p-8 md:p-10 rounded-2xl shadow-2xl w-full max-w-md border border-white/50">
        {/* Brand/Logo */}
        <div className="flex justify-center mb-4">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center shadow-lg">
            <span className="text-2xl">🔐</span>
          </div>
        </div>

        <h1 className="text-2xl md:text-3xl font-bold text-center text-slate-800 mb-1">
          Set New Password
        </h1>
        <p className="text-center text-slate-500 text-sm mb-8">
          Create a strong, new password for your account
        </p>

        {!token ? (
          /* ---------- Missing Token State ---------- */
          <div className="text-center space-y-4">
            <div className="bg-amber-50 border border-amber-200 text-amber-800 p-4 rounded-lg text-sm">
              <div className="text-2xl mb-2">⚠️</div>
              <p className="font-semibold mb-1">
                Invalid or Missing Reset Link
              </p>
              <p>
                No password reset token was found in the link. Please request a
                new password reset link.
              </p>
            </div>
            <Link
              to="/forgot-password"
              className="inline-block px-4 py-2.5 bg-gradient-to-r from-indigo-600 to-purple-600 text-white rounded-lg font-semibold text-sm shadow-md hover:from-indigo-700 hover:to-purple-700 hover:shadow-lg active:scale-[0.99] transition duration-200"
            >
              Request New Reset Link →
            </Link>
          </div>
        ) : success ? (
          /* ---------- Success State ---------- */
          <div className="text-center space-y-4">
            <div className="bg-emerald-50 border border-emerald-200 text-emerald-800 p-4 rounded-lg text-sm">
              <div className="text-3xl mb-2">🎉</div>
              <p className="font-semibold mb-1">Password Reset Complete!</p>
              <p>
                Your password has been updated. Redirecting you to sign in...
              </p>
            </div>
            <Link
              to="/login"
              className="inline-block px-4 py-2.5 bg-gradient-to-r from-indigo-600 to-purple-600 text-white rounded-lg font-semibold text-sm shadow-md hover:from-indigo-700 hover:to-purple-700 hover:shadow-lg active:scale-[0.99] transition duration-200"
            >
              Sign In Now →
            </Link>
          </div>
        ) : (
          /* ---------- Reset Form State ---------- */
          <form onSubmit={handleSubmit} noValidate>
            {/* Error Alert */}
            {error && (
              <div className="flex items-start gap-2 bg-red-50 border border-red-200 text-red-700 p-3 rounded-lg mb-5 text-sm">
                <span className="text-base leading-none mt-0.5">⚠️</span>
                <span>{error}</span>
              </div>
            )}

            {/* New Password */}
            <div className="mb-3">
              <label
                htmlFor="password"
                className="block mb-2 text-sm font-semibold text-slate-700"
              >
                New Password
              </label>
              <div className="relative">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 text-base">
                  🔒
                </span>
                <input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  autoComplete="new-password"
                  required
                  className="w-full pl-10 pr-11 py-2.5 border border-slate-300 rounded-lg bg-white text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition duration-200"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((v) => !v)}
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 text-sm focus:outline-none"
                >
                  {showPassword ? '🙈' : '👁️'}
                </button>
              </div>
            </div>

            {/* Password Policy Guidelines */}
            <div className="mb-4 p-3 bg-slate-50 border border-slate-200 rounded-lg text-xs space-y-1.5">
              <p className="font-semibold text-slate-700 mb-1">
                Password requirements:
              </p>
              <div
                className={`flex items-center gap-1.5 transition ${
                  isLengthValid
                    ? 'text-emerald-600 font-medium'
                    : 'text-slate-500'
                }`}
              >
                <span>{isLengthValid ? '✓' : '○'}</span>
                <span>At least 8 characters long</span>
              </div>
              <div
                className={`flex items-center gap-1.5 transition ${
                  hasUpper && hasLower
                    ? 'text-emerald-600 font-medium'
                    : 'text-slate-500'
                }`}
              >
                <span>{hasUpper && hasLower ? '✓' : '○'}</span>
                <span>Both uppercase (A-Z) and lowercase (a-z) letters</span>
              </div>
              <div
                className={`flex items-center gap-1.5 transition ${
                  hasNumber ? 'text-emerald-600 font-medium' : 'text-slate-500'
                }`}
              >
                <span>{hasNumber ? '✓' : '○'}</span>
                <span>At least one number (0-9)</span>
              </div>
              <div
                className={`flex items-center gap-1.5 transition ${
                  hasSpecial ? 'text-emerald-600 font-medium' : 'text-slate-500'
                }`}
              >
                <span>{hasSpecial ? '✓' : '○'}</span>
                <span>At least one special character (!@#$%^&*)</span>
              </div>
            </div>

            {/* Confirm New Password */}
            <div className="mb-5">
              <label
                htmlFor="confirmPassword"
                className="block mb-2 text-sm font-semibold text-slate-700"
              >
                Confirm New Password
              </label>
              <div className="relative">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 text-base">
                  🔒
                </span>
                <input
                  id="confirmPassword"
                  type={showConfirmPassword ? 'text' : 'password'}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="••••••••"
                  autoComplete="new-password"
                  required
                  className={`w-full pl-10 pr-11 py-2.5 border rounded-lg bg-white text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 transition duration-200 ${
                    confirmPassword.length === 0
                      ? 'border-slate-300 focus:ring-indigo-500 focus:border-transparent'
                      : passwordsMatch
                      ? 'border-emerald-400 focus:ring-emerald-500 focus:border-transparent'
                      : 'border-red-300 focus:ring-red-500 focus:border-transparent'
                  }`}
                />
                <button
                  type="button"
                  onClick={() => setShowConfirmPassword((v) => !v)}
                  aria-label={
                    showConfirmPassword ? 'Hide password' : 'Show password'
                  }
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 text-sm focus:outline-none"
                >
                  {showConfirmPassword ? '🙈' : '👁️'}
                </button>
              </div>
              {confirmPassword.length > 0 && (
                <p
                  className={`text-xs mt-1.5 ${
                    passwordsMatch ? 'text-emerald-600' : 'text-red-600'
                  }`}
                >
                  {passwordsMatch
                    ? '✓ Passwords match'
                    : '✗ Passwords do not match'}
                </p>
              )}
            </div>

            {/* Submit */}
            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 bg-gradient-to-r from-indigo-600 to-purple-600 text-white rounded-lg font-semibold shadow-md hover:from-indigo-700 hover:to-purple-700 hover:shadow-lg active:scale-[0.99] transition duration-200 disabled:opacity-60 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
              {loading && (
                <svg
                  className="animate-spin h-4 w-4 text-white"
                  xmlns="http://www.w3.org/2000/svg"
                  fill="none"
                  viewBox="0 0 24 24"
                >
                  <circle
                    className="opacity-25"
                    cx="12"
                    cy="12"
                    r="10"
                    stroke="currentColor"
                    strokeWidth="4"
                  />
                  <path
                    className="opacity-75"
                    fill="currentColor"
                    d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z"
                  />
                </svg>
              )}
              {loading ? 'Resetting Password...' : 'Reset Password'}
            </button>

            <p className="text-center mt-6 text-sm text-slate-600">
              <Link
                to="/login"
                className="text-indigo-600 font-semibold hover:text-indigo-800 hover:underline transition"
              >
                ← Back to Sign In
              </Link>
            </p>
          </form>
        )}
      </div>
    </div>
  );
}
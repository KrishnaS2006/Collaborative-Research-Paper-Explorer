import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function ForgotPassword() {
  const [email, setEmail] = useState('');
  const [error, setError] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  const [loading, setLoading] = useState(false);

  const { forgotPassword } = useAuth();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccessMessage('');

    const trimmedEmail = email.trim();

    if (!trimmedEmail) {
      setError('Please enter your email address.');
      return;
    }

    const emailRegex = /^[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,}$/;
    if (!emailRegex.test(trimmedEmail)) {
      setError('Please enter a valid email address.');
      return;
    }

    setLoading(true);
    try {
      const data = await forgotPassword(trimmedEmail);
      setSuccessMessage(
        data.message ||
          'If an account with that email exists, a password reset link has been sent.'
      );
    } catch (err) {
      setError(
        err.response?.data?.error ||
          'Unable to request password reset. Please try again later.'
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
            <span className="text-2xl">🔑</span>
          </div>
        </div>

        <h1 className="text-2xl md:text-3xl font-bold text-center text-slate-800 mb-1">
          Forgot Password?
        </h1>
        <p className="text-center text-slate-500 text-sm mb-8">
          No worries — we'll help you get back in
        </p>

        {successMessage ? (
          /* ---------- Success State ---------- */
          <div className="space-y-4">
            <div className="bg-emerald-50 border border-emerald-200 text-emerald-800 p-4 rounded-lg text-sm text-center">
              <div className="text-3xl mb-2">✉️</div>
              <p className="font-semibold mb-1">Check your inbox</p>
              <p>{successMessage}</p>
              <p className="text-xs text-emerald-600 mt-2">
                The link is valid for 15 minutes and can only be used once.
              </p>
            </div>

            <div className="text-center pt-2">
              <Link
                to="/login"
                className="text-indigo-600 font-semibold hover:text-indigo-800 hover:underline text-sm transition"
              >
                ← Back to Sign In
              </Link>
            </div>
          </div>
        ) : (
          /* ---------- Form State ---------- */
          <form onSubmit={handleSubmit} noValidate>
            {/* Error Alert */}
            {error && (
              <div className="flex items-start gap-2 bg-red-50 border border-red-200 text-red-700 p-3 rounded-lg mb-5 text-sm">
                <span className="text-base leading-none mt-0.5">⚠️</span>
                <span>{error}</span>
              </div>
            )}

            {/* Email */}
            <div className="mb-6">
              <label
                htmlFor="email"
                className="block mb-2 text-sm font-semibold text-slate-700"
              >
                Email Address
              </label>
              <div className="relative">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 text-base">
                  ✉️
                </span>
                <input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@example.com"
                  autoComplete="email"
                  required
                  className="w-full pl-10 pr-4 py-2.5 border border-slate-300 rounded-lg bg-white text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition duration-200"
                />
              </div>
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
              {loading ? 'Sending Reset Link...' : 'Send Reset Link'}
            </button>

            {/* Divider */}
            <div className="flex items-center my-6">
              <div className="flex-1 h-px bg-slate-200" />
              <span className="px-3 text-xs text-slate-400 font-medium">OR</span>
              <div className="flex-1 h-px bg-slate-200" />
            </div>

            <p className="text-center text-sm text-slate-600">
              Remember your password?{' '}
              <Link
                to="/login"
                className="text-indigo-600 font-semibold hover:text-indigo-800 hover:underline transition"
              >
                Sign In
              </Link>
            </p>
          </form>
        )}
      </div>
    </div>
  );
}
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function ForgotPassword() {
  const [email, setEmail] = useState('');
  const [error, setError] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  const [devResetToken, setDevResetToken] = useState('');
  const [loading, setLoading] = useState(false);

  const { forgotPassword } = useAuth();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccessMessage('');
    setDevResetToken('');

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
      setSuccessMessage(data.message || 'If an account with that email exists, a password reset link has been sent.');
      if (data.devResetToken) {
        setDevResetToken(data.devResetToken);
      }
    } catch (err) {
      setError(
        err.response?.data?.error || 'Unable to request password reset. Please try again later.'
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 to-slate-200 font-sans p-4">
      <div className="bg-white p-8 md:p-10 rounded-xl shadow-xl w-full max-w-md">
        <h1 className="text-2xl font-bold text-center text-slate-800 mb-2">
          Forgot Password
        </h1>
        <p className="text-center text-slate-500 text-sm mb-6">
          Enter your registered email address and we will send you a password reset link.
        </p>

        {error && (
          <div className="bg-red-100 border border-red-200 text-red-700 p-3 rounded-lg mb-5 text-sm text-center">
            {error}
          </div>
        )}

        {successMessage ? (
          <div className="space-y-4">
            <div className="bg-emerald-50 border border-emerald-200 text-emerald-800 p-4 rounded-lg text-sm text-center">
              <div className="text-2xl mb-2">✉️</div>
              <p className="font-semibold mb-1">Check your inbox</p>
              <p>{successMessage}</p>
              <p className="text-xs text-emerald-600 mt-2">
                The link is valid for 15 minutes and can only be used once.
              </p>
            </div>

            {devResetToken && (
              <div className="bg-amber-50 border border-amber-300 p-3 rounded-lg text-xs text-amber-900">
                <span className="font-bold block mb-1">🛠️ Local Development Preview:</span>
                <p className="mb-2">A reset token was generated. Click below to proceed with testing:</p>
                <Link
                  to={`/reset-password?token=${encodeURIComponent(devResetToken)}`}
                  className="inline-block px-3 py-1.5 bg-amber-600 text-white font-semibold rounded hover:bg-amber-700"
                >
                  Open Reset Password Page →
                </Link>
              </div>
            )}

            <div className="text-center pt-2">
              <Link
                to="/login"
                className="text-indigo-600 font-semibold hover:underline text-sm"
              >
                ← Back to Sign In
              </Link>
            </div>
          </div>
        ) : (
          <form onSubmit={handleSubmit}>
            <div className="mb-6">
              <label className="block mb-2 text-sm font-semibold text-slate-700">
                Email Address
              </label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@example.com"
                required
                className="w-full px-4 py-2.5 border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition duration-200"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 bg-indigo-600 text-white rounded-lg font-semibold hover:bg-indigo-700 transition duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? 'Sending Reset Link...' : 'Send Reset Link'}
            </button>

            <p className="text-center mt-6 text-sm text-slate-600">
              Remember your password?{' '}
              <Link to="/login" className="text-indigo-600 font-semibold hover:underline">
                Sign In
              </Link>
            </p>
          </form>
        )}
      </div>
    </div>
  );
}

import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function Register() {
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('STUDENT'); // default
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const { register } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (!fullName || !email || !password || !role) {
      setError('Please fill in all fields.');
      return;
    }

    if (password.length < 6) {
      setError('Password must be at least 6 characters long.');
      return;
    }

    setLoading(true);
    try {
      await register(fullName, email, password, role);
      alert(`Registration successful as ${role}! Please sign in.`);
      navigate('/login');
    } catch (err) {
      setError(err.response?.data?.error || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 to-slate-200 font-sans py-10">
      <div className="bg-white p-10 rounded-xl shadow-xl w-full max-w-md">
        <h1 className="text-2xl font-bold text-center text-slate-800 mb-2">
          Create an Account
        </h1>
        <p className="text-center text-slate-500 text-sm mb-8">
          Join Paper Explorer today
        </p>

        {error && (
          <div className="bg-red-100 text-red-700 p-3 rounded-md mb-4 text-sm text-center">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit}>
          {/* Full Name */}
          <div className="mb-5">
            <label className="block mb-2 text-sm font-semibold text-slate-700">
              Full Name
            </label>
            <input
              type="text"
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              placeholder="John Doe"
              required
              className="w-full px-4 py-2 border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition duration-200"
            />
          </div>

          {/* Email */}
          <div className="mb-5">
            <label className="block mb-2 text-sm font-semibold text-slate-700">
              Email
            </label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
              required
              className="w-full px-4 py-2 border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition duration-200"
            />
          </div>

          {/* Password */}
          <div className="mb-5">
            <label className="block mb-2 text-sm font-semibold text-slate-700">
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              required
              className="w-full px-4 py-2 border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition duration-200"
            />
          </div>

          {/* Role Selection */}
          <div className="mb-6">
            <label className="block mb-2 text-sm font-semibold text-slate-700">
              I am a...
            </label>
            <div className="grid grid-cols-2 gap-3">
              {/* STUDENT Option */}
              <label
                className={`cursor-pointer border-2 rounded-lg p-3 text-center transition duration-200 ${
                  role === 'STUDENT'
                    ? 'border-indigo-600 bg-indigo-50'
                    : 'border-slate-200 hover:border-slate-300'
                }`}
              >
                <input
                  type="radio"
                  name="role"
                  value="STUDENT"
                  checked={role === 'STUDENT'}
                  onChange={(e) => setRole(e.target.value)}
                  className="hidden"
                />
                <div className="text-lg">🎓</div>
                <div className="font-semibold text-slate-800 text-sm mt-1">
                  Student
                </div>
                <div className="text-xs text-slate-500 mt-1">
                  Learning & exploring
                </div>
              </label>

              {/* RESEARCHER Option */}
              <label
                className={`cursor-pointer border-2 rounded-lg p-3 text-center transition duration-200 ${
                  role === 'RESEARCHER'
                    ? 'border-indigo-600 bg-indigo-50'
                    : 'border-slate-200 hover:border-slate-300'
                }`}
              >
                <input
                  type="radio"
                  name="role"
                  value="RESEARCHER"
                  checked={role === 'RESEARCHER'}
                  onChange={(e) => setRole(e.target.value)}
                  className="hidden"
                />
                <div className="text-lg">🔬</div>
                <div className="font-semibold text-slate-800 text-sm mt-1">
                  Researcher
                </div>
                <div className="text-xs text-slate-500 mt-1">
                  Publishing & collaborating
                </div>
              </label>
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 bg-indigo-600 text-white rounded-lg font-semibold hover:bg-indigo-700 transition duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? 'Creating Account...' : `Register as ${role === 'STUDENT' ? 'Student' : 'Researcher'}`}
          </button>
        </form>

        <p className="text-center mt-6 text-sm text-slate-600">
          Already have an account?{' '}
          <Link to="/login" className="text-indigo-600 font-semibold hover:underline">
            Sign In
          </Link>
        </p>
      </div>
    </div>
  );
}
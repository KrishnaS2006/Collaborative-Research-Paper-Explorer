import { useAuth } from '../context/AuthContext';
import { useNavigate } from 'react-router-dom';

export default function Dashboard() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <div className="min-h-screen bg-slate-100 p-8 font-sans">
      <div className="max-w-3xl mx-auto bg-white p-8 rounded-xl shadow-md">
        <h1 className="text-3xl font-bold text-slate-800 mb-6">
          Welcome, {user?.full_name}!
        </h1>

        <div className="space-y-3 mb-8">
          <p className="text-slate-700">
            <span className="font-semibold">Email:</span> {user?.email}
          </p>
          <p className="text-slate-700">
            <span className="font-semibold">Role:</span>{' '}
            <span className="inline-block px-2 py-1 bg-indigo-100 text-indigo-700 rounded text-sm">
              {user?.role}
            </span>
          </p>
        </div>

        <button
          onClick={handleLogout}
          className="px-6 py-2.5 bg-red-500 text-white rounded-lg font-semibold hover:bg-red-600 transition duration-200"
        >
          Logout
        </button>
      </div>
    </div>
  );
}
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
        <div className="flex items-center justify-between mb-6 pb-4 border-b border-slate-100">
          <div>
            <h1 className="text-3xl font-bold text-slate-800">
              Welcome, {user?.full_name}!
            </h1>
            <p className="text-slate-500 text-sm mt-1">
              Collaborative Research Paper Explorer Dashboard
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-semibold bg-emerald-100 text-emerald-800">
              ✓ Authenticated
            </span>
            <span className="hidden sm:inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium bg-slate-100 text-slate-600 border border-slate-200">
              ⏱ 30m Idle Protection
            </span>
          </div>
        </div>

        <div className="space-y-4 mb-8">
          <div className="p-4 bg-slate-50 rounded-lg space-y-3">
            <p className="text-slate-700">
              <span className="font-semibold">Email:</span> {user?.email}
            </p>
            <p className="text-slate-700">
              <span className="font-semibold">Role:</span>{' '}
              <span className="inline-block px-2 py-0.5 bg-indigo-100 text-indigo-700 font-medium rounded text-xs">
                {user?.role}
              </span>
            </p>
            {user?.affiliation && (
              <p className="text-slate-700">
                <span className="font-semibold">Affiliation:</span> {user.affiliation}
              </p>
            )}
            {user?.research_interests && user.research_interests.length > 0 && (
              <div>
                <span className="font-semibold text-slate-700 block mb-1.5">
                  Research Interests:
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {user.research_interests.map((interest) => (
                    <span
                      key={interest}
                      className="px-2.5 py-1 bg-indigo-50 border border-indigo-200 text-indigo-700 rounded-md text-xs font-medium"
                    >
                      {interest}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>

        <button
          onClick={handleLogout}
          className="px-6 py-2.5 bg-red-500 text-white rounded-lg font-semibold hover:bg-red-600 transition duration-200 cursor-pointer"
        >
          Logout
        </button>
      </div>
    </div>
  );
}
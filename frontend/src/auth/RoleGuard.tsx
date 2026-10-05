import { Navigate, Outlet } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { Role } from '../lib/models';

export function RoleGuard({ allowedRoles }: { allowedRoles: Role[] }) {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center" style={{ background: 'var(--color-parchment)' }}>
        <div className="text-graphite">Loading...</div>
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/" replace />;
  }

  if (!allowedRoles.includes(user.role)) {
    return (
      <div className="min-h-screen flex items-center justify-center flex-col gap-4" style={{ background: 'var(--color-parchment)' }}>
        <div className="text-graphite text-center">
          <p className="text-xl font-semibold mb-2">Access Denied</p>
          <p>You do not have permission to view this page.</p>
        </div>
      </div>
    );
  }

  return <Outlet />;
}

export function RootRedirect() {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center" style={{ background: 'var(--color-parchment)' }}>
        <div className="text-graphite">Loading...</div>
      </div>
    );
  }

  if (!user) {
    // If not logged in, show Login
    return null; // Handled by App.tsx conditionally rendering Login
  }

  if (user.role === Role.OPERATOR) {
    return <Navigate to="/operator/dashboard" replace />;
  } else if (user.role === Role.VALIDATOR) {
    return <Navigate to="/validator/queue" replace />;
  } else if (user.role === Role.MANAGEMENT) {
    return <Navigate to="/management/users" replace />;
  }

  return <div>Unknown role</div>;
}

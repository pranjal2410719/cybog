/**
 * Cybog Frontend Application Router & Layout
 *
 * Routing structure supporting clean operator routes:
 *  - /dashboard
 *  - /assessments
 *  - /assessments/new
 *  - /assessments/:id
 *  - /findings
 *  - /reports
 *  - /settings
 */

import { useState } from 'react';
import {
  createBrowserRouter,
  RouterProvider,
  Link,
  useNavigate,
  useLocation,
  useParams,
  Outlet,
  Navigate,
} from 'react-router-dom';

import DashboardPage from './pages/Dashboard';
import AssessmentsPage from './pages/Assessments';
import { AssessmentWizard } from './pages/AssessmentWizard';
import { AssessmentDetail } from './components/AssessmentDetail';
import FindingsPage from './pages/FindingsPage';
import ReportsPage from './pages/ReportsPage';
import { SettingsPage } from './pages/management/Settings';
import { AssessmentReportsPage } from './pages/operator/AssessmentReportsPage';
import { ValidationFindingDetail } from './pages/validator/ValidationFindingDetail';
import { AuditLogPage } from './pages/management/AuditLog';
import { UserManagementPage } from './pages/management/Users';
import { ValidationQueuePage } from './pages/validator/ValidationQueue';

import { RoleGuard, RootRedirect } from './auth/RoleGuard';
import { OperatorLayout } from './layouts/OperatorLayout';
import { ValidatorLayout } from './layouts/ValidatorLayout';
import { ManagementLayout } from './layouts/ManagementLayout';
import { Role } from './lib/models';
import { ErrorBoundary } from './components/ErrorBoundary';
import { AuthProvider, useAuth } from './context/AuthContext';
import { Login } from './components/Login';

// ─── Icons ────────────────────────────────────────────────────────────────────

function IconShield({ className = '' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  );
}

function IconGrid({ className = '' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="3" width="7" height="7" />
      <rect x="14" y="3" width="7" height="7" />
      <rect x="3" y="14" width="7" height="7" />
      <rect x="14" y="14" width="7" height="7" />
    </svg>
  );
}

function IconList({ className = '' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round">
      <line x1="8" y1="6" x2="21" y2="6" />
      <line x1="8" y1="12" x2="21" y2="12" />
      <line x1="8" y1="18" x2="21" y2="18" />
      <line x1="3" y1="6" x2="3.01" y2="6" />
      <line x1="3" y1="12" x2="3.01" y2="12" />
      <line x1="3" y1="18" x2="3.01" y2="18" />
    </svg>
  );
}

function IconPlus({ className = '' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round">
      <line x1="12" y1="5" x2="12" y2="19" />
      <line x1="5" y1="12" x2="19" y2="12" />
    </svg>
  );
}

function IconSearch({ className = '' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round">
      <circle cx="11" cy="11" r="8" />
      <line x1="21" y1="21" x2="16.65" y2="16.65" />
    </svg>
  );
}

function IconFileText({ className = '' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <polyline points="14 2 14 8 20 8" />
      <line x1="16" y1="13" x2="8" y2="13" />
      <line x1="16" y1="17" x2="8" y2="17" />
      <polyline points="10 9 9 9 8 9" />
    </svg>
  );
}

function IconSettings({ className = '' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
    </svg>
  );
}

function IconMenu({ className = '' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round">
      <line x1="3" y1="6" x2="21" y2="6" />
      <line x1="3" y1="12" x2="21" y2="12" />
      <line x1="3" y1="18" x2="21" y2="18" />
    </svg>
  );
}

function IconX({ className = '' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round">
      <line x1="18" y1="6" x2="6" y2="18" />
      <line x1="6" y1="6" x2="18" y2="18" />
    </svg>
  );
}

// ─── Nav Item ─────────────────────────────────────────────────────────────────

function NavItem({
  to,
  icon,
  label,
  active,
  onClick,
}: {
  to: string;
  icon: React.ReactNode;
  label: string;
  active: boolean;
  onClick?: () => void;
}) {
  return (
    <Link
      to={to}
      onClick={onClick}
      className={`
        flex items-center gap-3 px-3 py-2.5 rounded-[12px] text-[15px] font-medium
        transition-colors duration-150 w-full
        ${active
          ? 'bg-deep-teal text-white'
          : 'text-graphite hover:text-ink hover:bg-warm-mist/40'
        }
      `}
    >
      <span className="w-5 h-5 flex-shrink-0">{icon}</span>
      <span>{label}</span>
    </Link>
  );
}

// ─── Sidebar ──────────────────────────────────────────────────────────────────

function Sidebar({ onClose }: { onClose?: () => void }) {
  const location = useLocation();

  const nav = [
    { to: '/dashboard', label: 'Dashboard', icon: <IconGrid className="w-5 h-5" /> },
    { to: '/assessments', label: 'Assessments', icon: <IconList className="w-5 h-5" /> },
    { to: '/assessments/new', label: 'New Assessment', icon: <IconPlus className="w-5 h-5" /> },
    { to: '/findings', label: 'Findings', icon: <IconSearch className="w-5 h-5" /> },
    { to: '/reports', label: 'Reports', icon: <IconFileText className="w-5 h-5" /> },
    { to: '/settings', label: 'Settings', icon: <IconSettings className="w-5 h-5" /> },
  ];

  return (
    <aside className="flex flex-col h-full py-5 px-3 gap-1">
      {/* Brand */}
      <div className="flex items-center gap-2.5 px-3 mb-6">
        <div className="w-7 h-7 flex items-center justify-center text-ink">
          <IconShield className="w-7 h-7" />
        </div>
        <span className="text-[17px] font-bold text-ink tracking-tight">Cybog</span>
        <span
          className="ml-auto text-[10px] font-bold text-white px-2 py-0.5 rounded-full leading-none"
          style={{ background: '#016a71' }}
        >
          MVP v1.0
        </span>
        {onClose && (
          <button
            onClick={onClose}
            aria-label="Close menu"
            className="ml-2 text-graphite hover:text-ink transition-colors"
          >
            <IconX className="w-5 h-5" />
          </button>
        )}
      </div>

      {/* Section label */}
      <p className="px-3 mb-1 text-[11px] text-graphite uppercase tracking-wide font-semibold">Operator Nav</p>

      {/* Nav links */}
      <nav className="flex flex-col gap-1">
        {nav.map((item) => (
          <NavItem
            key={item.to}
            to={item.to}
            icon={item.icon}
            label={item.label}
            active={
              item.to === '/dashboard'
                ? location.pathname === '/dashboard' || location.pathname === '/operator/dashboard'
                : item.to === '/assessments'
                ? location.pathname === '/assessments' || location.pathname === '/operator/assessments'
                : location.pathname.startsWith(item.to)
            }
            onClick={onClose}
          />
        ))}
      </nav>

      {/* Footer */}
      <div className="mt-auto px-3 pt-6 border-t border-warm-mist">
        <p className="text-[12px] font-medium text-graphite">Cybog Security Platform</p>
        <p className="text-[11px] text-ash mt-0.5">Automated Recon & Scan Engine</p>
      </div>
    </aside>
  );
}

// ─── Main Layout ──────────────────────────────────────────────────────────────

function MainAppLayout() {
  const [drawerOpen, setDrawerOpen] = useState(false);
  const { logout, user } = useAuth();

  return (
    <div className="min-h-screen flex" style={{ background: 'var(--color-parchment)' }}>
      {/* ── Desktop Sidebar ── */}
      <div
        className="hidden lg:flex flex-col flex-shrink-0 border-r border-warm-mist"
        style={{
          width: '260px',
          background: '#f3f0eb',
          position: 'sticky',
          top: 0,
          height: '100vh',
          overflowY: 'auto',
        }}
      >
        <Sidebar />
        <div className="mt-auto px-3 pb-4 border-t border-warm-mist pt-3">
          {user && (
            <div className="flex flex-col gap-2">
              <span className="text-[12px] font-medium text-graphite px-3">
                {user.name} ({user.role})
              </span>
              <button
                onClick={logout}
                className="text-left px-3 py-1.5 text-[13px] text-graphite hover:text-ink hover:bg-warm-mist/40 rounded-[12px] transition-colors font-medium"
              >
                Sign Out
              </button>
            </div>
          )}
        </div>
      </div>

      {/* ── Mobile Drawer Overlay ── */}
      {drawerOpen && (
        <div className="fixed inset-0 z-40 lg:hidden" aria-modal="true" role="dialog">
          <div
            className="absolute inset-0 bg-ink/20"
            onClick={() => setDrawerOpen(false)}
          />
          <div
            className="absolute left-0 top-0 h-full w-64 border-r border-warm-mist shadow-subtle z-50 flex flex-col"
            style={{ background: '#f3f0eb' }}
          >
            <Sidebar onClose={() => setDrawerOpen(false)} />
            <div className="mt-auto px-3 pb-4 border-t border-warm-mist pt-3">
              {user && (
                <div className="flex flex-col gap-2">
                  <span className="text-[12px] font-medium text-graphite px-3">{user.name}</span>
                  <button
                    onClick={() => {
                      logout();
                      setDrawerOpen(false);
                    }}
                    className="text-left px-3 py-1.5 text-[13px] text-graphite hover:text-ink hover:bg-warm-mist/40 rounded-[12px] transition-colors"
                  >
                    Sign Out
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ── Main content area ── */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Mobile top bar */}
        <header
          className="lg:hidden flex items-center gap-3 px-4 py-3 border-b border-warm-mist sticky top-0 z-30"
          style={{ background: '#f3f0eb' }}
        >
          <button
            onClick={() => setDrawerOpen(true)}
            aria-label="Open menu"
            className="text-graphite hover:text-ink transition-colors"
          >
            <IconMenu className="w-5 h-5" />
          </button>
          <div className="flex items-center gap-2">
            <IconShield className="w-5 h-5 text-ink" />
            <span className="text-[15px] font-bold text-ink">Cybog</span>
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 px-4 sm:px-6 lg:px-10 py-8">
          <div className="max-w-[1000px] mx-auto w-full">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}

// ─── Wrapper Components ───────────────────────────────────────────────────────

function AssessmentDetailPageWrapper() {
  const navigate = useNavigate();
  const { id: assessmentId } = useParams<{ id: string }>();
  if (!assessmentId) {
    return <div className="p-4 text-center">Assessment not found</div>;
  }
  return (
    <AssessmentDetail
      assessmentId={assessmentId}
      onBack={() => navigate('/assessments')}
    />
  );
}

function AssessmentReportsPageWrapper() {
  const navigate = useNavigate();
  const { id: assessmentId } = useParams<{ id: string }>();
  if (!assessmentId) {
    return <div className="p-4 text-center">Assessment not found</div>;
  }
  return (
    <AssessmentReportsPage
      assessmentId={assessmentId}
      onBack={() => navigate(`/assessments/${assessmentId}`)}
    />
  );
}

function ValidationFindingDetailPageWrapper() {
  const navigate = useNavigate();
  const { assessmentId, findingId } = useParams<{ assessmentId?: string; findingId?: string }>();
  return (
    <ValidationFindingDetail
      assessmentId={assessmentId || ''}
      findingId={findingId || ''}
      onBack={() => navigate(`/validator/queue/${assessmentId}`)}
    />
  );
}

function RootRoute() {
  const { user } = useAuth();
  if (!user) {
    return <Login />;
  }
  return <RootRedirect />;
}

// ─── Router Definition ────────────────────────────────────────────────────────

const router = createBrowserRouter([
  {
    path: '/',
    element: <RootRoute />,
    errorElement: (
      <ErrorBoundary>
        <RootRoute />
      </ErrorBoundary>
    ),
  },
  {
    path: '/',
    element: <RoleGuard allowedRoles={[Role.OPERATOR, Role.VALIDATOR, Role.MANAGEMENT]} />,
    errorElement: (
      <ErrorBoundary>
        <RootRoute />
      </ErrorBoundary>
    ),
    children: [
      {
        element: <MainAppLayout />,
        children: [
          { path: 'dashboard', element: <DashboardPage /> },
          { path: 'assessments', element: <AssessmentsPage /> },
          { path: 'assessments/new', element: <AssessmentWizard /> },
          { path: 'assessments/:id', element: <AssessmentDetailPageWrapper /> },
          { path: 'assessments/:id/reports', element: <AssessmentReportsPageWrapper /> },
          { path: 'findings', element: <FindingsPage /> },
          { path: 'reports', element: <ReportsPage /> },
          { path: 'settings', element: <SettingsPage /> },
        ],
      },
    ],
  },
  {
    path: '/operator',
    element: <RoleGuard allowedRoles={[Role.OPERATOR, Role.VALIDATOR, Role.MANAGEMENT]} />,
    errorElement: (
      <ErrorBoundary>
        <RootRoute />
      </ErrorBoundary>
    ),
    children: [
      {
        element: <MainAppLayout />,
        children: [
          { path: 'dashboard', element: <DashboardPage /> },
          { path: 'assessments', element: <AssessmentsPage /> },
          { path: 'assessments/new', element: <AssessmentWizard /> },
          { path: 'assessments/:id', element: <AssessmentDetailPageWrapper /> },
          { path: 'assessments/:id/reports', element: <AssessmentReportsPageWrapper /> },
          { path: 'findings', element: <FindingsPage /> },
          { path: 'reports', element: <ReportsPage /> },
          { path: 'settings', element: <SettingsPage /> },
        ],
      },
    ],
  },
  {
    path: '/validator',
    element: <RoleGuard allowedRoles={[Role.VALIDATOR, Role.MANAGEMENT]} />,
    errorElement: (
      <ErrorBoundary>
        <RootRoute />
      </ErrorBoundary>
    ),
    children: [
      {
        element: <ValidatorLayout />,
        children: [
          { path: 'queue', element: <ValidationQueuePage /> },
          { path: 'queue/:assessmentId', element: <ValidationQueuePage /> },
          { path: 'queue/:assessmentId/findings/:findingId', element: <ValidationFindingDetailPageWrapper /> },
        ],
      },
    ],
  },
  {
    path: '/management',
    element: <RoleGuard allowedRoles={[Role.MANAGEMENT]} />,
    errorElement: (
      <ErrorBoundary>
        <RootRoute />
      </ErrorBoundary>
    ),
    children: [
      {
        element: <ManagementLayout />,
        children: [
          { path: 'users', element: <UserManagementPage /> },
          { path: 'audit', element: <AuditLogPage /> },
          { path: 'settings', element: <SettingsPage /> },
        ],
      },
    ],
  },
  {
    path: '*',
    element: <Navigate to="/dashboard" replace />,
  },
]);

export default function App() {
  return (
    <ErrorBoundary>
      <AuthProvider>
        <RouterProvider router={router} />
      </AuthProvider>
    </ErrorBoundary>
  );
}
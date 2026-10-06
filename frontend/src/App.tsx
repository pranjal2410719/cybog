/**
 * Cybog Frontend Application
 *
 * Two-pane Perplexity-style layout:
 *  - Fixed left sidebar (~260px) with brand mark + nav
 *  - Centered main column (max 900px)
 *
 * Mobile: sidebar collapses into a top bar with a hamburger drawer.
 */

import { useState, useEffect } from 'react';
import {
  createBrowserRouter,
  RouterProvider,
  Link,
  useNavigate,
  useLocation,
  Outlet,
} from 'react-router-dom';
import { AssessmentDashboard } from './components/AssessmentDashboard';
import { AssessmentCreationForm } from './components/AssessmentForm';
import { AssessmentDetail } from './components/AssessmentDetail';

// ─── Icons (inline SVGs, ink / graphite coloured) ────────────────────────────

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

function IconPlus({ className = '' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round">
      <line x1="12" y1="5" x2="12" y2="19" />
      <line x1="5" y1="12" x2="19" y2="12" />
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
        flex items-center gap-3 px-3 py-2.5 rounded-[12px] text-[16px] font-normal
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
    { to: '/', label: 'Dashboard', icon: <IconGrid className="w-5 h-5" /> },
    { to: '/assessments/new', label: 'New Assessment', icon: <IconPlus className="w-5 h-5" /> },
  ];

  return (
    <aside className="flex flex-col h-full py-5 px-3 gap-1">
      {/* Brand */}
      <div className="flex items-center gap-2.5 px-3 mb-6">
        <div className="w-7 h-7 flex items-center justify-center text-ink">
          <IconShield className="w-7 h-7" />
        </div>
        <span className="text-[16px] font-medium text-ink tracking-tight">Cybor</span>
        <span
          className="ml-auto text-[11px] font-medium text-white px-2 py-0.5 rounded-full leading-none"
          style={{ background: 'var(--color-deep-teal)' }}
        >
          NEW
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
      <p className="px-3 mb-1 text-[12px] text-graphite uppercase tracking-wide">Navigation</p>

      {/* Nav links */}
      <nav className="flex flex-col gap-0.5">
        {nav.map((item) => (
          <NavItem
            key={item.to}
            to={item.to}
            icon={item.icon}
            label={item.label}
            active={
              item.to === '/'
                ? location.pathname === '/'
                : location.pathname.startsWith(item.to)
            }
            onClick={onClose}
          />
        ))}
      </nav>

      {/* Footer */}
      <div className="mt-auto px-3 pt-6 border-t border-warm-mist">
        <p className="text-[12px] text-ash">Cybor Security Platform</p>
        <p className="text-[11px] text-ash mt-0.5">v1.0.0 · Authorized use only</p>
      </div>
    </aside>
  );
}

import { AuthProvider, useAuth } from './context/AuthContext';
import { Login } from './components/Login';

// ─── Layout ───────────────────────────────────────────────────────────────────

function Layout() {
  const [drawerOpen, setDrawerOpen] = useState(false);
  const { logout, user } = useAuth();

  return (
    <div className="min-h-screen flex" style={{ background: 'var(--color-parchment)' }}>

      {/* ── Desktop Sidebar ── */}
      <div
        className="hidden lg:flex flex-col flex-shrink-0 border-r border-warm-mist"
        style={{
          width: '260px',
          background: '#f3f0eb', /* one shade darker than parchment */
          position: 'sticky',
          top: 0,
          height: '100vh',
          overflowY: 'auto',
        }}
      >
        <Sidebar />
        <div className="mt-auto px-3 pb-4">
           {user && (
             <div className="flex flex-col gap-2">
                <span className="text-[12px] text-graphite px-3">{user.name} ({user.role})</span>
                <button
                  onClick={logout}
                  className="text-left px-3 py-2 text-[13px] text-graphite hover:text-ink hover:bg-warm-mist/40 rounded-[12px] transition-colors"
                >
                  Sign Out
                </button>
             </div>
           )}
        </div>
      </div>

      {/* ── Mobile Drawer Overlay ── */}
      {drawerOpen && (
        <div
          className="fixed inset-0 z-40 lg:hidden"
          aria-modal="true"
          role="dialog"
        >
          {/* Backdrop */}
          <div
            className="absolute inset-0 bg-ink/20"
            onClick={() => setDrawerOpen(false)}
          />
          {/* Drawer */}
          <div
            className="absolute left-0 top-0 h-full w-64 border-r border-warm-mist shadow-subtle z-50 flex flex-col"
            style={{ background: '#f3f0eb' }}
          >
            <Sidebar onClose={() => setDrawerOpen(false)} />
            <div className="mt-auto px-3 pb-4">
              {user && (
                 <div className="flex flex-col gap-2 border-t border-warm-mist pt-4">
                    <span className="text-[12px] text-graphite px-3">{user.name}</span>
                    <button
                      onClick={() => {
                        logout();
                        setDrawerOpen(false);
                      }}
                      className="text-left px-3 py-2 text-[13px] text-graphite hover:text-ink hover:bg-warm-mist/40 rounded-[12px] transition-colors"
                    >
                      Sign Out
                    </button>
                 </div>
               )}
            </div>
          </div>
        </div>
      )}

      {/* ── Main area ── */}
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
            <span className="text-[15px] font-medium text-ink">Cybor</span>
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 px-4 sm:px-6 lg:px-10 py-8">
          <div className="max-w-[900px] mx-auto w-full">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}

// ─── Page wrappers ────────────────────────────────────────────────────────────

function DashboardPage() {
  const navigate = useNavigate();
  return (
    <AssessmentDashboard
      onSelectAssessment={(id) => navigate(`/operator/assessments/${id}`)}
    />
  );
}

function AssessmentsPage() {
  return <AssessmentDashboard />;
}

function NewAssessmentPage() {
  const navigate = useNavigate();
  return (
    <div className="max-w-2xl mx-auto">
      <AssessmentCreationForm
        onAssessmentCreated={(id) => navigate(`/operator/assessments/${id}`)}
      />
    </div>
  );
}

function AssessmentDetailPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const assessmentId = location.pathname.split('/')[2];
  return (
    <AssessmentDetail
      assessmentId={assessmentId}
      onBack={() => navigate('/operator/dashboard')}
    />
  );
}

import { getPendingValidation, validateFinding, rejectFinding } from './api/validation';
import type { FindingResponse } from './lib/models';

function AssessmentFindingsPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const assessmentId = location.pathname.split('/')[2];
  
  const [findings, setFindings] = useState<FindingResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    getPendingValidation(assessmentId)
      .then(res => {
        setFindings(res.findings);
        setLoading(false);
      })
      .catch(err => {
        setError(String(err?.message || 'Failed to load findings'));
        setLoading(false);
      });
  }, [assessmentId]);

  const handleValidate = async (findingId: string, verdict: 'confirm' | 'reject') => {
    try {
      if (verdict === 'confirm') {
        await validateFinding(assessmentId, findingId, 'Confirmed by validator');
      } else {
        await rejectFinding(assessmentId, findingId, 'Rejected by validator');
      }
      setFindings(prev => prev.filter(f => f.finding_id !== findingId));
    } catch (err: any) {
      alert(`Failed to ${verdict} finding: ${String(err?.message || 'unknown error')}`);
    }
  };

  return (
    <div className="space-y-6">
      <button
        onClick={() => navigate(`/operator/assessments/${assessmentId}`)}
        className="px-3 py-1.5 text-[14px] text-graphite border border-warm-mist rounded-btn hover:text-ink hover:border-ash transition-colors"
      >
        ← Back
      </button>
      
      <div className="bg-soft-paper rounded-card border border-warm-mist shadow-subtle p-6">
        <h2 className="text-[16px] text-ink font-semibold mb-4">Pending Findings ({findings.length})</h2>
        {loading && <p className="text-graphite text-[14px]">Loading...</p>}
        {error && <p className="text-red-500 text-[14px]">{error}</p>}
        {!loading && !error && findings.length === 0 && (
          <p className="text-graphite text-[14px] text-center py-8">No findings awaiting validation.</p>
        )}
        {!loading && !error && findings.length > 0 && (
          <div className="space-y-4">
            {findings.map((f) => (
              <div key={f.finding_id} className="border border-warm-mist rounded-[8px] p-4 flex flex-col md:flex-row justify-between md:items-center gap-4 bg-[#fbf9f6]">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`px-2 py-0.5 rounded-[4px] text-[12px] font-medium border
                      ${f.severity === 'critical' ? 'bg-red-50 border-red-200 text-red-700' :
                        f.severity === 'high' ? 'bg-orange-50 border-orange-200 text-orange-700' :
                        f.severity === 'medium' ? 'bg-yellow-50 border-yellow-200 text-yellow-700' :
                        'bg-blue-50 border-blue-200 text-blue-700'}`}>
                      {f.severity.toUpperCase()}
                    </span>
                    <h3 className="text-[15px] font-medium text-ink">{f.title}</h3>
                  </div>
                  <p className="text-[13px] text-graphite mb-2">{f.description}</p>
                  <div className="text-[12px] text-graphite flex gap-4">
                    <span>Target: {f.target_domain}</span>
                    <span>Tool: {f.source_tool}</span>
                  </div>
                </div>
                <div className="flex gap-2">
                  <button 
                    onClick={() => handleValidate(f.finding_id, 'confirm')}
                    className="px-4 py-2 bg-green-50 hover:bg-green-100 text-green-700 border border-green-200 rounded-[8px] text-[13px] font-medium transition-colors"
                  >
                    Confirm
                  </button>
                  <button 
                    onClick={() => handleValidate(f.finding_id, 'reject')}
                    className="px-4 py-2 bg-red-50 hover:bg-red-100 text-red-700 border border-red-200 rounded-[8px] text-[13px] font-medium transition-colors"
                  >
                    Reject
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function AssessmentReportsPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const assessmentId = location.pathname.split('/')[2];
  return (
    <div className="space-y-6">
      <button
        onClick={() => navigate(`/operator/assessments/${assessmentId}`)}
        className="px-3 py-1.5 text-[14px] text-graphite border border-warm-mist rounded-btn hover:text-ink hover:border-ash transition-colors"
      >
        ← Back
      </button>
      <div className="text-center py-12 bg-soft-paper rounded-card border border-warm-mist shadow-subtle">
        <p className="text-graphite text-[14px]">Reports view — coming soon</p>
      </div>
    </div>
  );
}

import { RoleGuard, RootRedirect } from './auth/RoleGuard';
import { OperatorLayout } from './layouts/OperatorLayout';
import { ValidatorLayout } from './layouts/ValidatorLayout';
import { ManagementLayout } from './layouts/ManagementLayout';
import { Role } from './lib/models';
import { UserManagementPage } from './pages/management/Users';
import { ErrorBoundary } from './components/ErrorBoundary';

function RootRoute() {
  const { user } = useAuth();
  if (!user) {
    return <Login />;
  }
  return <RootRedirect />;
}

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
    path: '/operator',
    element: <RoleGuard allowedRoles={[Role.OPERATOR]} />,
    errorElement: (
      <ErrorBoundary>
        <RootRoute />
      </ErrorBoundary>
    ),
    children: [
      {
        element: <OperatorLayout />,
        children: [
          { path: 'dashboard', element: <DashboardPage /> },
          { path: 'assessments/new', element: <NewAssessmentPage /> },
          { path: 'assessments/:id', element: <AssessmentDetailPage /> },
          { path: 'assessments/:id/reports', element: <AssessmentReportsPage /> },
        ]
      }
    ]
  },
  {
    path: '/validator',
    element: <RoleGuard allowedRoles={[Role.VALIDATOR]} />,
    errorElement: (
      <ErrorBoundary>
        <RootRoute />
      </ErrorBoundary>
    ),
    children: [
      {
        element: <ValidatorLayout />,
        children: [
          { path: 'queue', element: <AssessmentFindingsPage /> },
          { path: 'queue/:id', element: <AssessmentFindingsPage /> },
        ]
      }
    ]
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
        ]
      }
    ]
  }
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
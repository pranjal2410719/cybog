/**
 * Cybog Frontend Application
 * 
 * Main React application with routing and layout.
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

// Layout component with header and navigation
function Layout() {
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const location = useLocation();

  return (
    <div className="min-h-screen bg-cyborg-dark">
      {/* Header */}
      <header className="bg-cyborg-dark border-b border-cyborg-border">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center">
              <Link to="/" className="flex items-center space-x-3">
                <div className="w-8 h-8 bg-cyborg-accent rounded-lg flex items-center justify-center">
                  <span className="text-cyborg-dark font-bold text-lg">C</span>
                </div>
                <span className="text-xl font-bold text-white">Cybog</span>
              </Link>
            </div>

            {/* Desktop Navigation */}
            <nav className="hidden md:flex space-x-8">
              <Link
                to="/"
                className={`text-sm font-medium transition-colors ${
                  location.pathname === '/'
                    ? 'text-cyborg-accent'
                    : 'text-cyborg-muted hover:text-white'
                }`}
              >
                Dashboard
              </Link>
              <Link
                to="/assessments"
                className={`text-sm font-medium transition-colors ${
                  location.pathname.startsWith('/assessments')
                    ? 'text-cyborg-accent'
                    : 'text-cyborg-muted hover:text-white'
                }`}
              >
                Assessments
              </Link>
            </nav>

            {/* Mobile menu button */}
            <div className="md:hidden">
              <button
                type="button"
                onClick={() => setIsMenuOpen(!isMenuOpen)}
                className="text-cyborg-muted hover:text-white"
              >
                <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d={isMenuOpen ? 'M6 18L18 6M6 6l12 12' : 'M4 6h16M4 12h16M4 18h16'}
                  />
                </svg>
              </button>
            </div>
          </div>
        </div>

        {/* Mobile Navigation */}
        {isMenuOpen && (
          <div className="md:hidden border-t border-cyborg-border">
            <div className="px-2 pt-2 pb-3 space-y-1">
              <Link
                to="/"
                onClick={() => setIsMenuOpen(false)}
                className={`block px-3 py-2 rounded-md text-base font-medium transition-colors ${
                  location.pathname === '/'
                    ? 'bg-cyborg-card text-cyborg-accent'
                    : 'text-cyborg-muted hover:bg-cyborg-card hover:text-white'
                }`}
              >
                Dashboard
              </Link>
              <Link
                to="/assessments"
                onClick={() => setIsMenuOpen(false)}
                className={`block px-3 py-2 rounded-md text-base font-medium transition-colors ${
                  location.pathname.startsWith('/assessments')
                    ? 'bg-cyborg-card text-cyborg-accent'
                    : 'text-cyborg-muted hover:bg-cyborg-card hover:text-white'
                }`}
              >
                Assessments
              </Link>
            </div>
          </div>
        )}
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <Outlet />
      </main>

      {/* Footer */}
      <footer className="bg-cyborg-dark border-t border-cyborg-border mt-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="flex items-center justify-between">
            <div className="text-sm text-cyborg-muted">
              Cybog Security Assessment Platform
            </div>
            <div className="text-sm text-cyborg-muted">
              Version 1.0.0
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}

// Dashboard Page
function DashboardPage() {
  const navigate = useNavigate();

  return (
    <AssessmentDashboard
      onSelectAssessment={(id) => navigate(`/assessments/${id}`)}
    />
  );
}

// Assessments List Page
function AssessmentsPage() {
  return <AssessmentDashboard />;
}

// New Assessment Page
function NewAssessmentPage() {
  const navigate = useNavigate();

  return (
    <div className="max-w-2xl mx-auto">
      <AssessmentCreationForm
        onAssessmentCreated={(id) => navigate(`/assessments/${id}`)}
      />
    </div>
  );
}

// Assessment Detail Page
function AssessmentDetailPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const assessmentId = location.pathname.split('/')[2];

  return (
    <AssessmentDetail
      assessmentId={assessmentId}
      onBack={() => navigate('/')}
    />
  );
}

// RESERVED for a later step: findings view under an assessment.
function AssessmentFindingsPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const assessmentId = location.pathname.split('/')[2];

  return (
    <div className="space-y-6">
      <button
        onClick={() => navigate(`/assessments/${assessmentId}`)}
        className="px-3 py-1 text-sm bg-cyborg-card border border-cyborg-border text-cyborg-muted rounded-lg hover:bg-cyborg-card/50 transition-colors"
      >
        Back
      </button>
      <div className="text-center py-12 bg-cyborg-card rounded-lg border border-cyborg-border">
        <div className="text-cyborg-muted">Findings view for assessment {assessmentId}</div>
        <p className="text-cyborg-muted text-sm mt-2">
          Reserved for a later step.
        </p>
      </div>
    </div>
  );
}

// RESERVED for a later step: reports view under an assessment.
function AssessmentReportsPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const assessmentId = location.pathname.split('/')[2];

  return (
    <div className="space-y-6">
      <button
        onClick={() => navigate(`/assessments/${assessmentId}`)}
        className="px-3 py-1 text-sm bg-cyborg-card border border-cyborg-border text-cyborg-muted rounded-lg hover:bg-cyborg-card/50 transition-colors"
      >
        Back
      </button>
      <div className="text-center py-12 bg-cyborg-card rounded-lg border border-cyborg-border">
        <div className="text-cyborg-muted">Reports view for assessment {assessmentId}</div>
        <p className="text-cyborg-muted text-sm mt-2">
          Reserved for a later step.
        </p>
      </div>
    </div>
  );
}

// Create router
const router = createBrowserRouter([
  {
    path: '/',
    element: <Layout />,
    children: [
      {
        path: '',
        element: <DashboardPage />,
      },
      {
        path: 'assessments',
        element: <AssessmentsPage />,
      },
      {
        path: 'assessments/new',
        element: <NewAssessmentPage />,
      },
      {
        path: 'assessments/:id',
        element: <AssessmentDetailPage />,
      },
      {
        path: 'assessments/:id/findings',
        element: <AssessmentFindingsPage />,
      },
      {
        path: 'assessments/:id/reports',
        element: <AssessmentReportsPage />,
      },
    ],
  },
]);

// App component
export default function App() {
  return <RouterProvider router={router} />;
}
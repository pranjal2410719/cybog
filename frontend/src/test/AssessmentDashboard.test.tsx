/**
 * Dashboard: the states that matter operationally.
 *
 * The critical distinction is EMPTY (the request succeeded and there is
 * genuinely nothing) versus ERROR (the request failed). Rendering an empty
 * list after a failed request tells the operator their assessments are gone
 * when they are actually unreachable.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AssessmentDashboard } from '../components/AssessmentDashboard';

const listAssessments = vi.fn();
const startAssessment = vi.fn();
const navigate = vi.fn();

vi.mock('../api', () => ({
  api: {
    listAssessments: (...a: unknown[]) => listAssessments(...a),
    startAssessment: (...a: unknown[]) => startAssessment(...a),
    cancelAssessment: vi.fn(),
  },
}));
vi.mock('react-router-dom', () => ({ useNavigate: () => navigate }));

function assessment(overrides: Record<string, unknown> = {}) {
  return {
    assessment_id: 'assess-1',
    name: 'Nightly scan',
    status: 'RUNNING',
    created_at: '2026-10-01T10:00:00',
    updated_at: '2026-10-01T10:05:00',
    profile: 'standard',
    artifact_root: '/tmp/assess-1',
    progress: {
      total_targets: 4,
      completed_targets: 1,
      total_jobs: 28,
      completed_jobs: 7,
      failed_jobs: 0,
      completion_percentage: 25,
    },
    findings_count: 3,
    pending_validation_count: 1,
    ...overrides,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('loading state', () => {
  it('shows a loading indicator before data arrives', () => {
    listAssessments.mockReturnValue(new Promise(() => {}));
    render(<AssessmentDashboard />);
    expect(screen.getByText(/loading/i)).toBeInTheDocument();
  });
});

describe('empty state', () => {
  it('shows "No assessments yet" and a create action on a successful empty list', async () => {
    listAssessments.mockResolvedValue([]);
    render(<AssessmentDashboard />);

    await waitFor(() => expect(screen.getByText('No assessments yet')).toBeInTheDocument());
    expect(
      screen.getByRole('button', { name: /create your first assessment/i })
    ).toBeInTheDocument();
    // A successful empty result is not an error.
    expect(screen.queryByText('Failed to load assessments')).not.toBeInTheDocument();
  });
});

describe('error state', () => {
  it('shows an error with Retry instead of an empty list when the API fails', async () => {
    listAssessments.mockRejectedValue(new Error('network down'));
    render(<AssessmentDashboard />);

    await waitFor(() =>
      expect(screen.getByText('Failed to load assessments')).toBeInTheDocument()
    );
    // The key regression this guards: a failure must NOT masquerade as
    // "nothing here", which would hide an unreachable backend.
    expect(screen.queryByText('No assessments yet')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument();
  });

  it('re-requests when Retry is pressed', async () => {
    const user = userEvent.setup();
    listAssessments.mockRejectedValueOnce(new Error('boom'));
    render(<AssessmentDashboard />);

    await waitFor(() =>
      expect(screen.getByText('Failed to load assessments')).toBeInTheDocument()
    );
    listAssessments.mockResolvedValue([assessment()]);
    await user.click(screen.getByRole('button', { name: /retry/i }));

    await waitFor(() => expect(screen.getByText('Nightly scan')).toBeInTheDocument());
    expect(listAssessments).toHaveBeenCalledTimes(2);
  });
});

describe('rendering real assessments', () => {
  it('shows name, status and progress from the API', async () => {
    listAssessments.mockResolvedValue([assessment()]);
    render(<AssessmentDashboard />);

    await waitFor(() => expect(screen.getByText('Nightly scan')).toBeInTheDocument());
    expect(screen.getByText('RUNNING')).toBeInTheDocument();
    expect(screen.getByText('25.0%')).toBeInTheDocument();
  });

  it('renders findings and pending-validation counts', async () => {
    listAssessments.mockResolvedValue([assessment({ pending_validation_count: 2 })]);
    render(<AssessmentDashboard />);

    await waitFor(() => expect(screen.getByText('Nightly scan')).toBeInTheDocument());
    const pending = screen.getByText('Pending Validation:').parentElement;
    expect(pending?.textContent).toContain('2');
    const findings = screen.getByText('Findings:').parentElement;
    expect(findings?.textContent).toContain('3');
  });

  it('navigates in-app when an assessment is selected', async () => {
    const user = userEvent.setup();
    listAssessments.mockResolvedValue([assessment()]);
    render(<AssessmentDashboard onSelectAssessment={(id) => navigate(`/assessments/${id}`)} />);

    await waitFor(() => expect(screen.getByText('Nightly scan')).toBeInTheDocument());
    await user.click(screen.getByText('Nightly scan'));
    expect(navigate).toHaveBeenCalledWith('/assessments/assess-1');
  });

  it('offers Start only for a CREATED assessment', async () => {
    listAssessments.mockResolvedValue([
      assessment({ assessment_id: 'a', name: 'Fresh', status: 'CREATED' }),
    ]);
    render(<AssessmentDashboard />);

    await waitFor(() => expect(screen.getByText('Fresh')).toBeInTheDocument());
    expect(screen.getByRole('button', { name: /^start$/i })).toBeInTheDocument();
  });
});

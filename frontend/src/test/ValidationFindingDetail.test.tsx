/**
 * ValidationFindingDetail — validator decision flow.
 *
 * Asserts that confirm and reject actions call the correct backend
 * endpoints, that loading/error states render correctly, and that
 * a successful validation surfaces the success state.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ValidationFindingDetail } from '../pages/validator/ValidationFindingDetail';

const getFinding = vi.fn();
const validateFinding = vi.fn();
const rejectFinding = vi.fn();

vi.mock('../api', () => ({
  api: {
    getFinding: (...a: unknown[]) => getFinding(...a),
    validateFinding: (...a: unknown[]) => validateFinding(...a),
    rejectFinding: (...a: unknown[]) => rejectFinding(...a),
  },
}));

vi.mock('react-router-dom', () => ({ useNavigate: () => vi.fn() }));

function finding(overrides: Record<string, unknown> = {}) {
  return {
    finding_id: 'f-1',
    dedup_key: 'dedup-1',
    title: 'SQL Injection in login form',
    description: 'User input is not sanitized before being passed to the database.',
    severity: 'high',
    target_id: 't-1',
    target_domain: 'example.com',
    url: 'https://example.com/login',
    source_tool: 'nuclei',
    validation_status: 'NEEDS_VALIDATION',
    first_seen: '2026-10-01T10:00:00',
    last_seen: '2026-10-02T10:00:00',
    occurrence_count: 3,
    evidence: [{
      evidence_id: 'ev-1',
      tool: 'nuclei',
      raw_output: 'GET /login HTTP/1.1 200 OK',
      collected_at: '2026-10-02T10:00:00',
    }],
    ...overrides,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('loading state', () => {
  it('shows a loading skeleton while the finding is fetched', () => {
    getFinding.mockReturnValue(new Promise(() => {}));
    render(<ValidationFindingDetail assessmentId="a-1" findingId="f-1" onBack={vi.fn()} />);

    expect(screen.getByText('Validate Finding')).toBeInTheDocument();
    expect(screen.queryByText('Confirm as Valid')).not.toBeInTheDocument();
  });
});

describe('error state', () => {
  it('shows an error with a Retry option if the API fails', async () => {
    getFinding.mockRejectedValue(new Error('not found'));
    render(<ValidationFindingDetail assessmentId="a-1" findingId="f-1" onBack={vi.fn()} />);

    const alert = await screen.findByText(/failed to load finding/i);
    expect(alert).toBeInTheDocument();
    expect(screen.getByText('Retry')).toBeInTheDocument();
  });

  it('re-fetches the finding when Retry is pressed', async () => {
    getFinding.mockRejectedValueOnce(new Error('boom'));
    getFinding.mockResolvedValueOnce(finding());
    render(<ValidationFindingDetail assessmentId="a-1" findingId="f-1" onBack={vi.fn()} />);

    expect(await screen.findByText(/failed to load finding/i)).toBeInTheDocument();
    await userEvent.click(screen.getByText('Retry'));

    await waitFor(() => expect(screen.getByText('SQL Injection in login form')).toBeInTheDocument());
    expect(getFinding).toHaveBeenCalledTimes(2);
  });
});

describe('finding display', () => {
  it('renders severity, title, description, target, and tool', async () => {
    getFinding.mockResolvedValue(finding());
    render(<ValidationFindingDetail assessmentId="a-1" findingId="f-1" onBack={vi.fn()} />);

    await waitFor(() => expect(screen.getByText('SQL Injection in login form')).toBeInTheDocument());
    expect(screen.getByText('HIGH')).toBeInTheDocument();
    expect(screen.getByText(/User input is not sanitized/i)).toBeInTheDocument();
    expect(screen.getByText('example.com')).toBeInTheDocument();
    expect(screen.getByText('nuclei')).toBeInTheDocument();
  });

  it('renders raw evidence output when present', async () => {
    getFinding.mockResolvedValue(finding());
    render(<ValidationFindingDetail assessmentId="a-1" findingId="f-1" onBack={vi.fn()} />);

    await waitFor(() => expect(screen.getByText('SQL Injection in login form')).toBeInTheDocument());
    expect(screen.getByText(/GET \/login HTTP\/1.1 200 OK/)).toBeInTheDocument();
  });
});

describe('validation actions', () => {
  it('calls validateFinding on Confirm', async () => {
    const user = userEvent.setup();
    const onComplete = vi.fn();
    getFinding.mockResolvedValue(finding());
    validateFinding.mockResolvedValue({ success: true, finding_id: 'f-1' });

    render(
      <ValidationFindingDetail
        assessmentId="a-1"
        findingId="f-1"
        onBack={vi.fn()}
        onValidationComplete={onComplete}
      />
    );

    await waitFor(() => expect(screen.getByText('Confirm as Valid')).toBeInTheDocument());

    // The component uses prompt() for notes; mock it to return empty string (no notes)
    const originalPrompt = window.prompt;
    window.prompt = vi.fn().mockReturnValue('');

    await user.click(screen.getByText('Confirm as Valid'));

    await waitFor(() => expect(validateFinding).toHaveBeenCalledWith('a-1', 'f-1', ''));
    expect(onComplete).toHaveBeenCalled();
    expect(screen.getByText(/Finding has been validated/i)).toBeInTheDocument();

    window.prompt = originalPrompt;
  });

  it('calls rejectFinding on Reject', async () => {
    const user = userEvent.setup();
    const onComplete = vi.fn();
    getFinding.mockResolvedValue(finding());
    rejectFinding.mockResolvedValue({ success: true, finding_id: 'f-1' });

    render(
      <ValidationFindingDetail
        assessmentId="a-1"
        findingId="f-1"
        onBack={vi.fn()}
        onValidationComplete={onComplete}
      />
    );

    await waitFor(() => expect(screen.getByText('Reject as Invalid')).toBeInTheDocument());

    const originalPrompt = window.prompt;
    window.prompt = vi.fn().mockReturnValue('');

    await user.click(screen.getByText('Reject as Invalid'));

    await waitFor(() => expect(rejectFinding).toHaveBeenCalledWith('a-1', 'f-1', ''));
    expect(onComplete).toHaveBeenCalled();

    window.prompt = originalPrompt;
  });

  it('shows an error if validateFinding fails', async () => {
    const user = userEvent.setup();
    getFinding.mockResolvedValue(finding());
    validateFinding.mockRejectedValue(new Error('already validated'));

    render(<ValidationFindingDetail assessmentId="a-1" findingId="f-1" onBack={vi.fn()} />);

    await waitFor(() => expect(screen.getByText('Confirm as Valid')).toBeInTheDocument());

    const originalPrompt = window.prompt;
    window.prompt = vi.fn().mockReturnValue('');

    await user.click(screen.getByText('Confirm as Valid'));

    await waitFor(() => expect(screen.getByText(/validation failed/i)).toBeInTheDocument());

    window.prompt = originalPrompt;
  });
});

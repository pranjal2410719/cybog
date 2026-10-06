/**
 * AuditLogPage — displays system-wide audit events with filtering and CSV export.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AuditLogPage } from '../pages/management/AuditLog';

const getAuditEvents = vi.fn();

vi.mock('../api', () => ({
  api: {
    getAuditEvents: (...a: unknown[]) => getAuditEvents(...a),
  },
}));

vi.mock('react-router-dom', () => ({ useNavigate: () => vi.fn() }));

function event(overrides: Record<string, unknown> = {}) {
  return {
    event_id: 'evt-1',
    user_id: 'usr-1',
    user_name: 'Alice Smith',
    action: 'assessment_create',
    assessment_id: 'a-1',
    target: 'POST /assessments',
    detail: 'Created assessment "Nightly scan"',
    ip_address: '192.168.1.10',
    timestamp: '2026-10-01T10:00:00',
    ...overrides,
  };
}

beforeEach(() => {
  vi.clearAllMocks();

  getAuditEvents.mockResolvedValue({
    events: [
      event(),
      event({
        event_id: 'evt-2',
        user_id: 'usr-2',
        user_name: 'Bob Jones',
        action: 'finding_validate',
        assessment_id: 'a-2',
        target: 'POST /findings/f-1/validate',
        detail: 'Confirmed finding "SQL Injection"',
        ip_address: '192.168.1.20',
        timestamp: '2026-10-02T10:00:00',
      }),
    ],
  });
});

describe('loading and display', () => {
  it('fetches and renders audit events on mount', async () => {
    render(<AuditLogPage />);

    await waitFor(() => expect(screen.getByText('Alice Smith')).toBeInTheDocument());
    expect(screen.getByText(/assessment create/i)).toBeInTheDocument();
  });
});

describe('filtering', () => {
  it('filters by assessment_id', async () => {
    render(<AuditLogPage />);

    await waitFor(() => expect(screen.getByText('Alice Smith')).toBeInTheDocument());

    await userEvent.selectOptions(
      screen.getByLabelText(/assessment filter/i),
      'a-1'
    );

    await waitFor(() => {
      // Bob Jones should be filtered out, Alice Smith should remain
      const alice = screen.getByText(/Alice Smith/i);
      const bob = screen.getByText(/Bob Jones/i);
      expect(alice).toBeInTheDocument();
      expect(bob).not.toBeInTheDocument();
    });
    expect(getAuditEvents).toHaveBeenCalledWith({ assessment_id: 'a-1' });
  });

  it('filters by search term', async () => {
    render(<AuditLogPage />);

    await waitFor(() => expect(screen.getByText('Alice Smith')).toBeInTheDocument());

    await userEvent.type(screen.getByLabelText(/search by user/i'), 'Bob');

    await waitFor(() => {
      expect(screen.getByText(/Bob Jones/i)).toBeInTheDocument();
    });
  });
});

describe('CSV export', () => {
  it('creates a downloadable CSV when Export is clicked', async () => {
    const user = userEvent.setup();
    const mockClick = vi.fn();
    const mockCreateObjectURL = vi.fn().mockReturnValue('blob:url');
    const mockRevokeObjectURL = vi.fn();
    const mockAnchor = { href: '', download: '', click: mockClick };

    vi.spyOn(window, 'URL').property('createObjectURL').mockImplementation(mockCreateObjectURL as any);
    vi.spyOn(window, 'URL').property('revokeObjectURL').mockImplementation(mockRevokeObjectURL as any);
    vi.spyOn(document, 'createElement').mockReturnValue(mockAnchor as any);

    render(<AuditLogPage />);

    await waitFor(() => expect(screen.getByText(/Alice Smith/i)).toBeInTheDocument());
    await user.click(screen.getByLabelText('Export CSV'));

    expect(mockCreateObjectURL).toHaveBeenCalledWith(expect.any(Blob));
    expect(mockAnchor.download).toMatch(/audit-events-.*\.csv/);
    expect(mockClick).toHaveBeenCalled();

    window.URL.createObjectURL.mockRestore();
    window.URL.revokeObjectURL.mockRestore();
  });
});
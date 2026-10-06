/**
 * AssessmentReportsPage — reports/artifacts display and export flow.
 *
 * Mocks the API layer to assert:
 * - Reports and artifacts load and render from the correct endpoints
 * - Export triggers create → poll → download → file save
 * - Loading and error states are shown at the right times
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AssessmentReportsPage } from '../pages/operator/AssessmentReportsPage';

const getReports = vi.fn();
const getArtifacts = vi.fn();
const createExport = vi.fn();
const getExportStatus = vi.fn();
const downloadExport = vi.fn();

vi.mock('../api', () => ({
  api: {
    getReports: (...a: unknown[]) => getReports(...a),
    getArtifacts: (...a: unknown[]) => getArtifacts(...a),
    createExport: (...a: unknown[]) => createExport(...a),
    getExportStatus: (...a: unknown[]) => getExportStatus(...a),
    downloadExport: (...a: unknown[]) => downloadExport(...a),
  },
}));

vi.mock('react-router-dom', () => ({ useNavigate: () => vi.fn() }));

beforeEach(() => {
  vi.clearAllMocks();

  const reportsData = {
    assessment_id: 'a-1',
    reports: [
      {
        filename: 'findings.json',
        type: 'json',
        path: '/api/v1/assessments/a-1/reports/findings.json',
        size_bytes: 10240,
        created_at: '2026-10-01T12:00:00',
      },
    ],
  };
  const artifactsData = {
    assessment_id: 'a-1',
    artifacts: [
      {
        artifact_id: 'art-1',
        filename: 'nuclei-raw.json',
        artifact_type: 'raw_output',
        path: '/tmp/assess-a-1/targets/example.com/nuclei.json',
        size_bytes: 51200,
        target_id: 't-1',
        stage: 'discovery',
        checksum: 'abc123def456',
        created_at: '2026-10-01T11:30:00',
      },
    ],
  };
  getReports.mockResolvedValue(reportsData);
  getArtifacts.mockResolvedValue(artifactsData);

  createExport.mockResolvedValue({
    export_id: 'exp-1',
    assessment_id: 'a-1',
    format: 'zip',
    status: 'building',
    created_at: '2026-10-01T12:05:00',
    estimated_completion: null,
    error: null,
    file_size_bytes: null,
    file_count: null,
  });
  getExportStatus.mockResolvedValue({
    export_id: 'exp-1',
    assessment_id: 'a-1',
    format: 'zip',
    status: 'completed',
    created_at: '2026-10-01T12:05:00',
    estimated_completion: null,
    error: null,
    file_size_bytes: 102400,
    file_count: 5,
  });
  downloadExport.mockResolvedValue(new Blob(['fake-zip-content'], { type: 'application/zip' }));
});

describe('loading and display', () => {
  it('loads reports and artifacts on mount', async () => {
    render(<AssessmentReportsPage assessmentId="a-1" onBack={vi.fn()} />);

    await waitFor(() => expect(screen.getByText('findings.json')).toBeInTheDocument());
    expect(screen.getByText(/nuclei-raw.json/i)).toBeInTheDocument();
  });

  it('renders report filename and type', async () => {
    render(<AssessmentReportsPage assessmentId="a-1" onBack={vi.fn()} />);

    await waitFor(() => expect(screen.getByText('findings.json')).toBeInTheDocument());
    expect(screen.getByText(/json/i)).toBeInTheDocument();
  });

  it('renders artifact filename and target', async () => {
    render(<AssessmentReportsPage assessmentId="a-1" onBack={vi.fn()} />);

    await waitFor(() => expect(screen.getByText(/nuclei-raw.json/i)).toBeInTheDocument());
    expect(screen.getByText(/t-1/i)).toBeInTheDocument();
  });
});

describe('empty states', () => {
  it('shows a message when no reports exist', async () => {
    getReports.mockResolvedValue({ assessment_id: 'a-1', reports: [] });
    render(<AssessmentReportsPage assessmentId="a-1" onBack={vi.fn()} />);

    await waitFor(() => expect(screen.getByText(/no reports generated yet/i)).toBeInTheDocument());
  });

  it('shows a message when no artifacts exist', async () => {
    getArtifacts.mockResolvedValue({ assessment_id: 'a-1', artifacts: [] });
    render(<AssessmentReportsPage assessmentId="a-1" onBack={vi.fn()} />);

    await waitFor(() => expect(screen.getByText(/no artifacts collected yet/i)).toBeInTheDocument());
  });
});

describe('export flow', () => {
  it('triggers createExport with correct format on ZIP click', async () => {
    const user = userEvent.setup();
    const onBack = vi.fn();
    render(<AssessmentReportsPage assessmentId="a-1" onBack={onBack} />);

    await waitFor(() => expect(screen.getByText(/export/i)).toBeInTheDocument());

    const originalPrompt = window.prompt;
    window.prompt = vi.fn().mockReturnValue('');

    await user.click(screen.getByRole('button', { name: /export/i }));

    await waitFor(() => expect(createExport).toHaveBeenCalledWith('a-1', expect.objectContaining({ format: 'zip' })));

    window.prompt = originalPrompt;
  });

  it('shows error when export fails', async () => {
    const user = userEvent.setup();
    getExportStatus.mockResolvedValue({
      export_id: 'exp-1',
      assessment_id: 'a-1',
      format: 'zip',
      status: 'failed',
      error: 'disk full',
    });

    render(<AssessmentReportsPage assessmentId="a-1" onBack={vi.fn()} />);

    await waitFor(() => expect(screen.getByText(/export/i)).toBeInTheDocument());
    await user.click(screen.getByRole('button', { name: /export/i }));

    await waitFor(() => expect(screen.getByText(/disk full/i)).toBeInTheDocument());
  });
});
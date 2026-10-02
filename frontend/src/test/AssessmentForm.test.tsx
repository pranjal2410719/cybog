/**
 * Assessment creation form: mode switching, normalization preview, review,
 * and the create -> start sequence.
 *
 * The API module is mocked so these tests assert the UI contract (what is
 * previewed, what is POSTed, what happens when start fails) without a network.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AssessmentCreationForm } from '../components/AssessmentForm';

const createAssessment = vi.fn();
const startAssessment = vi.fn();

vi.mock('../api', () => ({
  api: {
    createAssessment: (...args: unknown[]) => createAssessment(...args),
    startAssessment: (...args: unknown[]) => startAssessment(...args),
  },
}));

beforeEach(() => {
  vi.clearAllMocks();
  createAssessment.mockResolvedValue({ assessment_id: 'assess-1' });
  startAssessment.mockResolvedValue({ assessment_id: 'assess-1', status: 'RUNNING' });
});

function renderForm(onCreated?: (id: string) => void) {
  return render(<AssessmentCreationForm onAssessmentCreated={onCreated} />);
}

async function fillName(user: ReturnType<typeof userEvent.setup>) {
  await user.type(screen.getByPlaceholderText('My Security Assessment'), 'Test Assessment');
}

describe('mode switching', () => {
  it('defaults to single-target mode', () => {
    renderForm();
    expect(screen.getByRole('button', { name: /single target/i })).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/example\.com/i)).toBeInTheDocument();
  });

  it('switches to bulk mode and shows the file picker', async () => {
    const user = userEvent.setup();
    renderForm();
    await user.click(screen.getByRole('button', { name: /multiple targets/i }));
    expect(screen.getByText(/drop a targets \.txt file/i)).toBeInTheDocument();
  });
});

describe('single target mode', () => {
  it('normalizes a URL and shows it as VALID before submitting', async () => {
    const user = userEvent.setup();
    renderForm();
    await user.type(screen.getByPlaceholderText(/example\.com/i), 'https://example.com/admin');

    expect(await screen.findByText('VALID')).toBeInTheDocument();
    // The preview shows the reduced host, not the raw URL.
    expect(screen.getByText('example.com')).toBeInTheDocument();
  });

  it('marks an invalid target and blocks submission', async () => {
    const user = userEvent.setup();
    renderForm();
    await fillName(user);
    await user.type(screen.getByPlaceholderText(/example\.com/i), 'not a domain');

    expect(await screen.findByText('INVALID')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /start assessment/i })).toBeDisabled();
  });

  it('does not call the API until the user submits', async () => {
    const user = userEvent.setup();
    renderForm();
    await user.type(screen.getByPlaceholderText(/example\.com/i), 'example.com');
    expect(createAssessment).not.toHaveBeenCalled();
  });
});

describe('bulk target mode', () => {
  it('parses an uploaded manifest, reports the count, and shows each target', async () => {
    const user = userEvent.setup();
    renderForm();
    await user.click(screen.getByRole('button', { name: /multiple targets/i }));

    const file = new File(
      ['example.com\nexample.org\nexample.com\n# note\n'],
      'targets.txt',
      { type: 'text/plain' }
    );
    await user.upload(screen.getByLabelText(/choose targets file/i), file);

    const detected = await screen.findByText(/targets detected/i);
    // 2 unique + 1 duplicate = 3 rows shown; the comment is skipped entirely
    expect(detected.textContent).toMatch(/3/);
    expect(screen.getAllByText('example.org').length).toBeGreaterThan(0);
    expect(screen.getByText('DUPLICATE')).toBeInTheDocument();
  });

  it('never starts execution automatically on upload', async () => {
    const user = userEvent.setup();
    renderForm();
    await user.click(screen.getByRole('button', { name: /multiple targets/i }));

    const file = new File(['example.com\n'], 'targets.txt', { type: 'text/plain' });
    await user.upload(screen.getByLabelText(/choose targets file/i), file);

    await waitFor(() => expect(screen.getByText(/targets detected/i)).toBeInTheDocument());
    expect(createAssessment).not.toHaveBeenCalled();
    expect(startAssessment).not.toHaveBeenCalled();
  });
});

describe('creation flow', () => {
  it('creates then starts the assessment, and reports the new id', async () => {
    const user = userEvent.setup();
    const onCreated = vi.fn();
    renderForm(onCreated);

    await fillName(user);
    await user.type(screen.getByPlaceholderText(/example\.com/i), 'example.com');
    await user.click(screen.getByRole('button', { name: /start assessment/i }));

    await waitFor(() => expect(onCreated).toHaveBeenCalledWith('assess-1'));
    expect(startAssessment).toHaveBeenCalledWith('assess-1');
  });

  /**
   * The backend's _is_file_content() only reports "content" for a value with a
   * newline, so a bare domain would be read as a filesystem path. This asserts
   * the payload is always newline-terminated.
   */
  it('sends newline-terminated targets and scope payloads', async () => {
    const user = userEvent.setup();
    renderForm();

    await fillName(user);
    await user.type(screen.getByPlaceholderText(/example\.com/i), 'https://example.com/admin');
    await user.click(screen.getByRole('button', { name: /start assessment/i }));

    await waitFor(() => expect(createAssessment).toHaveBeenCalled());
    const payload = createAssessment.mock.calls[0][0];
    expect(payload.targets_file).toBe('example.com\n');
    // Scope defaults to the target domains.
    expect(payload.scope_file).toBe('example.com\n');
    expect(payload.name).toBe('Test Assessment');
  });

  it('surfaces a create failure and does not start anything', async () => {
    const user = userEvent.setup();
    createAssessment.mockRejectedValue({ response: { data: { detail: 'scope mismatch' } } });
    renderForm();

    await fillName(user);
    await user.type(screen.getByPlaceholderText(/example\.com/i), 'example.com');
    await user.click(screen.getByRole('button', { name: /start assessment/i }));

    expect(await screen.findByText('scope mismatch')).toBeInTheDocument();
    expect(startAssessment).not.toHaveBeenCalled();
  });

  it('reports a create-ok / start-failed partial outcome', async () => {
    const user = userEvent.setup();
    startAssessment.mockRejectedValue({ response: { data: { detail: 'tool missing' } } });
    renderForm();

    await fillName(user);
    await user.type(screen.getByPlaceholderText(/example\.com/i), 'example.com');
    await user.click(screen.getByRole('button', { name: /start assessment/i }));

    expect(await screen.findByText(/was created but could not be started/i)).toBeInTheDocument();
  });
});

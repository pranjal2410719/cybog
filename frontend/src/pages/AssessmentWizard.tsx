/**
 * Guided 5-Step New Assessment Wizard
 *
 * Steps:
 * 01 Target          — Input single/multiple targets, validate, scope file preview ("Targets loaded: N")
 * 02 Authorization   — Explicit operator authorization, calls POST /assessments + POST /authorize
 * 03 Scan Profile    — Quick / Standard / Full profile selection with actual stage breakdown
 * 04 Review          — Configuration summary + runs mandatory POST /preflight check
 * 05 Start           — Sends POST /start and redirects to live monitoring
 */

import { useState, useMemo, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api';
import { useAuth } from '../context/AuthContext';
import { TargetInput } from '../components/TargetInput';
import { TargetPreview } from '../components/TargetPreview';
import {
  buildScopeContent,
  buildTargetsContent,
  createTargetEntry,
  parseScopeText,
  parseTargetsText,
  submittableTargets,
  type TargetEntry,
} from '../components/TargetUtils';
import type { PreflightCheck } from '../api/assessments';

type WizardStep = 1 | 2 | 3 | 4 | 5;
type TargetMode = 'single' | 'multiple';
type ProfileType = 'standard' | 'quick' | 'full';

interface ProfileInfo {
  id: ProfileType;
  name: string;
  tagline: string;
  description: string;
  stages: Array<{ id: string; name: string; tool: string }>;
  speed: string;
  depth: string;
}

const PROFILES_INFO: ProfileInfo[] = [
  {
    id: 'quick',
    name: 'QUICK',
    tagline: 'Fast Reconnaissance & Surface Probing',
    description: 'Rapid passive subdomain discovery, DNS resolution, port scanning, and HTTP service verification.',
    stages: [
      { id: 'subfinder', name: 'Discovering Assets', tool: 'Subfinder' },
      { id: 'dnsx', name: 'Resolving DNS', tool: 'DNSX' },
      { id: 'httpx', name: 'Scanning Services', tool: 'HTTPX' },
      { id: 'naabu', name: 'Port Discovery', tool: 'Naabu' },
    ],
    speed: '~1-3 minutes',
    depth: 'Light',
  },
  {
    id: 'standard',
    name: 'STANDARD',
    tagline: 'Full Assessment Pipeline (Default)',
    description: 'Complete pipeline including web crawling, directory fuzzing, and template vulnerability scanning.',
    stages: [
      { id: 'subfinder', name: 'Discovering Assets', tool: 'Subfinder' },
      { id: 'dnsx', name: 'Resolving DNS', tool: 'DNSX' },
      { id: 'httpx', name: 'Scanning Services', tool: 'HTTPX' },
      { id: 'naabu', name: 'Port Discovery', tool: 'Naabu' },
      { id: 'katana', name: 'Finding Endpoints', tool: 'Katana' },
      { id: 'ffuf', name: 'Content Discovery', tool: 'FFUF' },
      { id: 'nuclei', name: 'Vulnerability Scanning', tool: 'Nuclei' },
    ],
    speed: '~5-15 minutes',
    depth: 'Standard',
  },
  {
    id: 'full',
    name: 'FULL',
    tagline: 'Deepest Vulnerability & Route Audit',
    description: 'Deepest scan with maximum crawl depth, expanded fuzzing wordlists, and full severity vulnerability templates.',
    stages: [
      { id: 'subfinder', name: 'Discovering Assets', tool: 'Subfinder' },
      { id: 'dnsx', name: 'Resolving DNS', tool: 'DNSX' },
      { id: 'httpx', name: 'Scanning Services', tool: 'HTTPX' },
      { id: 'naabu', name: 'Port Discovery', tool: 'Naabu' },
      { id: 'katana', name: 'Finding Endpoints (Deep)', tool: 'Katana' },
      { id: 'ffuf', name: 'Content Discovery (Full)', tool: 'FFUF' },
      { id: 'nuclei', name: 'Vulnerability Scanning (Full)', tool: 'Nuclei' },
    ],
    speed: '~15-45 minutes',
    depth: 'Exhaustive',
  },
];

export function AssessmentWizard() {
  const navigate = useNavigate();
  const { user } = useAuth();

  // Wizard state
  const [step, setStep] = useState<WizardStep>(1);
  const [name, setName] = useState('');
  const [mode, setMode] = useState<TargetMode>('single');
  const [singleTarget, setSingleTarget] = useState('');
  const [entries, setEntries] = useState<TargetEntry[]>([]);
  const [targetsFileName, setTargetsFileName] = useState('');
  const [scopePatterns, setScopePatterns] = useState<string[]>([]);
  const [scopeFileName, setScopeFileName] = useState('');

  // Step 2 Authorization state
  const [authorized, setAuthorized] = useState(false);
  const [createdAssessmentId, setCreatedAssessmentId] = useState<string | null>(null);

  // Step 3 Profile state
  const [profile, setProfile] = useState<ProfileType>('standard');

  // Step 4 Preflight state
  const [preflightLoading, setPreflightLoading] = useState(false);
  const [preflightReady, setPreflightReady] = useState<boolean | null>(null);
  const [preflightChecks, setPreflightChecks] = useState<PreflightCheck[]>([]);

  // General loading & error
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Target helpers
  const readText = (file: File, apply: (text: string) => void) => {
    const reader = new FileReader();
    reader.onload = (e) => apply(e.target?.result as string);
    reader.onerror = () => setError(`Could not read ${file.name}`);
    reader.readAsText(file);
  };

  const handleTargetsFile = (file: File) => {
    setTargetsFileName(file.name);
    readText(file, (text) => setEntries(parseTargetsText(text)));
  };

  const handleScopeFile = (file: File) => {
    setScopeFileName(file.name);
    readText(file, (text) => setScopePatterns(parseScopeText(text)));
  };

  const effectiveEntries: TargetEntry[] = useMemo(() => {
    if (mode === 'single') {
      return singleTarget.trim() === '' ? [] : [createTargetEntry(singleTarget)];
    }
    return entries;
  }, [mode, singleTarget, entries]);

  const submittable = submittableTargets(effectiveEntries);
  const hasInvalid = effectiveEntries.some((e) => e.status === 'INVALID');

  // Step 1 -> Step 2 validation
  const canAdvanceFromStep1 = name.trim() !== '' && submittable.length > 0;

  // Step 2 Authorization action
  const handleAuthorizeStep = async () => {
    if (!authorized || submittable.length === 0) return;
    setLoading(true);
    setError(null);

    const targetsContent = buildTargetsContent(effectiveEntries);
    const scopePatternsToSend =
      scopePatterns.length > 0 ? scopePatterns : submittable.map((t) => t.normalized);
    const scopeContent = buildScopeContent(scopePatternsToSend);

    try {
      // 1. Create assessment if not already created
      let assessmentId = createdAssessmentId;
      if (!assessmentId) {
        const created = await api.createAssessment({
          name: name.trim(),
          targets_file: targetsContent,
          scope_file: scopeContent,
          profile,
        });
        assessmentId = created.assessment_id;
        setCreatedAssessmentId(created.assessment_id);
      }

      // 2. Authorize assessment
      await api.authorizeAssessment(assessmentId);
      setStep(3);
    } catch (err: any) {
      console.error('Failed authorization step:', err);
      setError(err?.message || 'Failed to authorize assessment');
    } finally {
      setLoading(false);
    }
  };

  // Step 3 Profile selection -> Step 4 Review
  const handleSelectProfileStep = (p: ProfileType) => {
    setProfile(p);
    setStep(4);
  };

  // Run preflight whenever reaching Step 4
  useEffect(() => {
    if (step === 4 && createdAssessmentId) {
      runPreflightCheck(createdAssessmentId);
    }
  }, [step, createdAssessmentId]);

  const runPreflightCheck = async (assessmentId: string) => {
    setPreflightLoading(true);
    setError(null);
    try {
      const res = await api.preflightAssessment(assessmentId);
      setPreflightReady(res.ready);
      setPreflightChecks(res.checks);
    } catch (err: any) {
      setError(err?.message || 'Preflight check failed');
      setPreflightReady(false);
    } finally {
      setPreflightLoading(false);
    }
  };

  // Step 5 Start Execution
  const handleStartExecution = async () => {
    if (!createdAssessmentId) return;
    setLoading(true);
    setError(null);

    try {
      await api.startAssessment(createdAssessmentId);
      navigate(`/assessments/${createdAssessmentId}`);
    } catch (err: any) {
      console.error('Failed to start assessment:', err);
      setError(err?.message || 'Failed to start assessment');
    } finally {
      setLoading(false);
    }
  };

  const selectedProfileInfo = PROFILES_INFO.find((p) => p.id === profile) || PROFILES_INFO[1];

  return (
    <div className="space-y-8 max-w-[850px] mx-auto">
      {/* Step Indicator Header */}
      <div>
        <h1 className="text-[22px] font-medium text-ink">New Assessment Setup</h1>
        <p className="text-[14px] text-graphite mt-1">
          Guided setup for target admission, human authorization, profile selection, and preflight review.
        </p>
      </div>

      {/* Progress Stepper */}
      <div className="flex items-center justify-between border-b border-warm-mist pb-4 flex-wrap gap-2">
        {[
          { num: 1, label: '01 Target' },
          { num: 2, label: '02 Authorization' },
          { num: 3, label: '03 Scan Profile' },
          { num: 4, label: '04 Review' },
          { num: 5, label: '05 Start' },
        ].map((s) => {
          const isActive = step === s.num;
          const isDone = step > s.num;

          return (
            <div key={s.num} className="flex items-center gap-2">
              <span
                className={`w-7 h-7 rounded-full flex items-center justify-center text-[12px] font-medium transition-colors ${
                  isActive
                    ? 'bg-deep-teal text-white'
                    : isDone
                    ? 'bg-ink text-white'
                    : 'bg-warm-mist text-graphite'
                }`}
              >
                {isDone ? '✓' : s.num}
              </span>
              <span
                className={`text-[13px] font-medium ${
                  isActive ? 'text-ink font-semibold' : isDone ? 'text-graphite' : 'text-ash'
                }`}
              >
                {s.label}
              </span>
            </div>
          );
        })}
      </div>

      {/* Error notification */}
      {error && (
        <div
          className="px-4 py-3 rounded-card text-[14px] flex items-center justify-between"
          style={{ background: '#fdf3f3', border: '1px solid #f5c6c6', color: '#c0392b' }}
        >
          <span>{error}</span>
          <button onClick={() => setError(null)} className="text-[12px] font-medium underline">
            Dismiss
          </button>
        </div>
      )}

      {/* ── STEP 01: TARGET ── */}
      {step === 1 && (
        <div className="space-y-6 rounded-card border border-warm-mist shadow-subtle p-6" style={{ background: '#fdfbfa' }}>
          <div>
            <h2 className="text-[18px] font-medium text-ink">01 Target Configuration</h2>
            <p className="text-[13px] text-graphite mt-1">
              Provide the assessment name, target domains, and optional scope restrictions.
            </p>
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-[13px] text-graphite mb-1.5 font-medium">Assessment Name</label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Production Infrastructure Scan"
                className="input-glow w-full px-4 py-2.5 rounded-input text-[15px] text-ink outline-none"
                style={{ background: '#faf8f5' }}
              />
            </div>

            <div>
              <label className="block text-[13px] text-graphite mb-1.5 font-medium">Target Mode</label>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => setMode('single')}
                  className={`px-4 py-1.5 rounded-chip text-[14px] font-normal border transition-colors ${
                    mode === 'single' ? 'bg-deep-teal text-white border-deep-teal' : 'bg-transparent text-graphite border-warm-mist'
                  }`}
                >
                  Single Target
                </button>
                <button
                  type="button"
                  onClick={() => setMode('multiple')}
                  className={`px-4 py-1.5 rounded-chip text-[14px] font-normal border transition-colors ${
                    mode === 'multiple' ? 'bg-deep-teal text-white border-deep-teal' : 'bg-transparent text-graphite border-warm-mist'
                  }`}
                >
                  Multiple Targets (.txt)
                </button>
              </div>
            </div>

            {mode === 'single' ? (
              <TargetInput value={singleTarget} onChange={setSingleTarget} />
            ) : (
              <div className="space-y-3">
                <label className="block text-[13px] text-graphite font-medium">Targets File Upload</label>
                <input
                  type="file"
                  accept=".txt"
                  onChange={(e) => {
                    const f = e.target.files?.[0];
                    if (f) handleTargetsFile(f);
                  }}
                  className="block w-full text-[13px] text-graphite border border-warm-mist rounded-input p-2"
                />
                {targetsFileName && <p className="text-[12px] text-deep-teal font-medium">File: {targetsFileName}</p>}
              </div>
            )}

            {/* Scope File */}
            <div>
              <label className="block text-[13px] text-graphite mb-1 font-medium">Authorized Scope (.txt File - Optional)</label>
              <p className="text-[12px] text-graphite mb-2">
                Defaults to the target domain(s). Upload a custom scope file if restricting specific subdomains or wildcards.
              </p>
              <input
                type="file"
                accept=".txt"
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) handleScopeFile(f);
                }}
                className="block w-full text-[13px] text-graphite border border-warm-mist rounded-input p-2"
              />
              {scopeFileName && <p className="text-[12px] text-deep-teal font-medium">Scope file: {scopeFileName}</p>}
            </div>

            {/* Targets Loaded & Preview */}
            {effectiveEntries.length > 0 && (
              <div className="space-y-2 pt-2 border-t border-warm-mist">
                <div className="flex items-center justify-between">
                  <span className="text-[14px] font-medium text-ink">
                    Targets loaded: <strong className="text-deep-teal">{submittable.length}</strong>
                  </span>
                  {hasInvalid && <span className="text-[12px] text-red-600 font-medium">Some invalid entries found</span>}
                </div>
                <TargetPreview entries={effectiveEntries} />
              </div>
            )}
          </div>

          <div className="flex justify-end pt-4">
            <button
              type="button"
              disabled={!canAdvanceFromStep1}
              onClick={() => setStep(2)}
              className="px-5 py-2.5 text-[14px] font-medium text-white rounded-input transition-opacity disabled:opacity-40 disabled:cursor-not-allowed"
              style={{ background: '#27251e' }}
            >
              Continue to Authorization →
            </button>
          </div>
        </div>
      )}

      {/* ── STEP 02: AUTHORIZATION ── */}
      {step === 2 && (
        <div className="space-y-6 rounded-card border border-warm-mist shadow-subtle p-6" style={{ background: '#fdfbfa' }}>
          <div>
            <h2 className="text-[18px] font-medium text-ink">02 Human Authorization Boundary</h2>
            <p className="text-[13px] text-graphite mt-1">
              Explicit operator confirmation is required prior to assessment admission.
            </p>
          </div>

          <div className="p-4 rounded-[12px] border border-amber-300/40 space-y-3" style={{ background: '#fff8ee' }}>
            <h3 className="text-[14px] font-semibold text-amber-900">Authorization Required</h3>
            <p className="text-[13px] text-amber-800">
              Confirm that you have explicit, documented authorization to perform security testing against the following target(s):
            </p>

            <div className="space-y-1 text-[13px] font-mono text-ink bg-white/70 p-3 rounded-[8px] border border-amber-200">
              <div><strong>Targets:</strong> {submittable.map((t) => t.normalized).join(', ')}</div>
              <div><strong>Scope:</strong> {scopePatterns.length > 0 ? scopePatterns.join(', ') : 'Default target boundary'}</div>
              <div><strong>Operator:</strong> {user?.name || user?.uid || 'Current Operator'}</div>
            </div>
          </div>

          <label className="flex items-start gap-3 px-4 py-3.5 rounded-card text-[13px] text-ink cursor-pointer" style={{ background: '#faf8f5', border: '1px solid #e8e2d6' }}>
            <input
              type="checkbox"
              checked={authorized}
              onChange={(e) => setAuthorized(e.target.checked)}
              className="mt-0.5 accent-[#27251e] w-4 h-4"
            />
            <span>
              I explicitly confirm that I hold proper authorization to perform security assessment scans against the target domains and scope listed above. This confirmation will be permanently logged in the audit trail.
            </span>
          </label>

          <div className="flex justify-between pt-4">
            <button
              type="button"
              onClick={() => setStep(1)}
              className="px-4 py-2 text-[13px] text-graphite border border-warm-mist rounded-btn hover:text-ink"
            >
              ← Back
            </button>
            <button
              type="button"
              disabled={!authorized || loading}
              onClick={handleAuthorizeStep}
              className="px-5 py-2.5 text-[14px] font-medium text-white rounded-input transition-opacity disabled:opacity-40 disabled:cursor-not-allowed"
              style={{ background: '#27251e' }}
            >
              {loading ? 'Confirming Authorization…' : 'Authorize & Select Profile →'}
            </button>
          </div>
        </div>
      )}

      {/* ── STEP 03: SCAN PROFILE ── */}
      {step === 3 && (
        <div className="space-y-6 rounded-card border border-warm-mist shadow-subtle p-6" style={{ background: '#fdfbfa' }}>
          <div>
            <h2 className="text-[18px] font-medium text-ink">03 Select Scan Profile</h2>
            <p className="text-[13px] text-graphite mt-1">
              Choose the execution characteristics and pipeline stages for this assessment.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {PROFILES_INFO.map((p) => {
              const isSelected = profile === p.id;

              return (
                <div
                  key={p.id}
                  onClick={() => setProfile(p.id)}
                  className={`cursor-pointer p-4 rounded-card border transition-all duration-150 flex flex-col justify-between ${
                    isSelected ? 'border-deep-teal shadow-md bg-[color-mix(in_oklch,#016a71_4%,#faf8f5)]' : 'border-warm-mist hover:border-ash bg-[#faf8f5]'
                  }`}
                >
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-[16px] font-bold text-ink">{p.name}</span>
                      {isSelected && <span className="text-[11px] px-2 py-0.5 rounded-chip font-medium text-white" style={{ background: '#016a71' }}>Selected</span>}
                    </div>
                    <p className="text-[12px] font-medium text-deep-teal mb-2">{p.tagline}</p>
                    <p className="text-[12px] text-graphite mb-4">{p.description}</p>

                    <div className="space-y-2 border-t border-warm-mist pt-3">
                      <span className="text-[11px] font-medium text-graphite uppercase tracking-wide">Included Stages ({p.stages.length})</span>
                      <ul className="space-y-1">
                        {p.stages.map((st) => (
                          <li key={st.id} className="text-[12px] text-ink flex items-center gap-1.5">
                            <span className="text-deep-teal font-bold">✓</span>
                            <span>{st.name}</span>
                            <span className="text-[11px] text-ash">({st.tool})</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>

                  <div className="mt-4 pt-3 border-t border-warm-mist flex justify-between text-[11px] text-graphite">
                    <span>Est. Time: <strong>{p.speed}</strong></span>
                    <span>Depth: <strong>{p.depth}</strong></span>
                  </div>
                </div>
              );
            })}
          </div>

          <div className="flex justify-between pt-4">
            <button
              type="button"
              onClick={() => setStep(2)}
              className="px-4 py-2 text-[13px] text-graphite border border-warm-mist rounded-btn hover:text-ink"
            >
              ← Back
            </button>
            <button
              type="button"
              onClick={() => setStep(4)}
              className="px-5 py-2.5 text-[14px] font-medium text-white rounded-input"
              style={{ background: '#27251e' }}
            >
              Continue to Review →
            </button>
          </div>
        </div>
      )}

      {/* ── STEP 04: REVIEW & PREFLIGHT ── */}
      {step === 4 && (
        <div className="space-y-6 rounded-card border border-warm-mist shadow-subtle p-6" style={{ background: '#fdfbfa' }}>
          <div>
            <h2 className="text-[18px] font-medium text-ink">04 Configuration Review & Preflight Check</h2>
            <p className="text-[13px] text-graphite mt-1">
              Verify your assessment parameters and view the mandatory backend preflight check results.
            </p>
          </div>

          {/* Configuration summary */}
          <div className="p-4 rounded-[12px] border border-warm-mist space-y-3" style={{ background: '#faf8f5' }}>
            <h3 className="text-[14px] font-medium text-ink">Assessment Configuration Summary</h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-[13px] text-graphite">
              <div><strong>Name:</strong> {name}</div>
              <div><strong>Assessment ID:</strong> <span className="font-mono">{createdAssessmentId}</span></div>
              <div><strong>Target Domains:</strong> {submittable.map((t) => t.normalized).join(', ')}</div>
              <div><strong>Authorized Scope:</strong> {scopePatterns.length > 0 ? scopePatterns.join(', ') : 'Default'}</div>
              <div><strong>Selected Profile:</strong> <span className="font-bold text-deep-teal uppercase">{profile}</span></div>
              <div><strong>Authorization Status:</strong> <span className="text-green-700 font-medium">Authorized ✓</span></div>
            </div>
          </div>

          {/* Mandatory Preflight Boundary */}
          <div className="space-y-3 border-t border-warm-mist pt-4">
            <div className="flex items-center justify-between">
              <h3 className="text-[14px] font-medium text-ink">Preflight Check Boundary</h3>
              {preflightLoading ? (
                <span className="text-[12px] text-graphite">Running checks…</span>
              ) : preflightReady === true ? (
                <span className="text-[12px] px-2.5 py-0.5 rounded-chip font-medium text-white bg-green-700">READY TO EXECUTE</span>
              ) : preflightReady === false ? (
                <span className="text-[12px] px-2.5 py-0.5 rounded-chip font-medium text-white bg-red-600">PREFLIGHT FAILED</span>
              ) : null}
            </div>

            {preflightLoading ? (
              <div className="p-4 text-center text-graphite text-[13px]">Verifying toolchain, storage, scope compiler, and targets…</div>
            ) : (
              <div className="space-y-2">
                {preflightChecks.map((check) => (
                  <div key={check.name} className="flex items-center justify-between p-2.5 rounded-[8px] border border-warm-mist text-[13px]" style={{ background: check.ok ? '#f0faf8' : '#fdf3f3' }}>
                    <div className="flex items-center gap-2">
                      <span className={check.ok ? 'text-green-700 font-bold' : 'text-red-600 font-bold'}>
                        {check.ok ? '✓' : '✕'}
                      </span>
                      <span className="font-medium text-ink capitalize">{check.name.replace(/_/g, ' ')}</span>
                    </div>
                    <span className="text-[12px] text-graphite">{check.detail}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="flex justify-between pt-4">
            <button
              type="button"
              onClick={() => setStep(3)}
              className="px-4 py-2 text-[13px] text-graphite border border-warm-mist rounded-btn hover:text-ink"
            >
              ← Back
            </button>
            <button
              type="button"
              disabled={preflightReady !== true || loading}
              onClick={() => setStep(5)}
              className="px-5 py-2.5 text-[14px] font-medium text-white rounded-input transition-opacity disabled:opacity-40 disabled:cursor-not-allowed"
              style={{ background: '#27251e' }}
            >
              Proceed to Start →
            </button>
          </div>
        </div>
      )}

      {/* ── STEP 05: START EXECUTION ── */}
      {step === 5 && (
        <div className="space-y-6 rounded-card border border-warm-mist shadow-subtle p-6 text-center" style={{ background: '#fdfbfa' }}>
          <div className="mx-auto w-12 h-12 rounded-full flex items-center justify-center text-white" style={{ background: '#016a71' }}>
            <span className="text-[20px]">⚡</span>
          </div>

          <div>
            <h2 className="text-[20px] font-medium text-ink">Ready to Launch Assessment</h2>
            <p className="text-[14px] text-graphite mt-1">
              All 7 preflight checks passed. Launch execution for <strong className="text-ink">{name}</strong>.
            </p>
          </div>

          <div className="p-4 rounded-[12px] border border-warm-mist text-left max-w-md mx-auto space-y-2 text-[13px] text-graphite" style={{ background: '#faf8f5' }}>
            <div><strong>Assessment ID:</strong> <span className="font-mono">{createdAssessmentId}</span></div>
            <div><strong>Profile:</strong> <span className="uppercase font-medium text-deep-teal">{profile}</span></div>
            <div><strong>Targets:</strong> {submittable.map((t) => t.normalized).join(', ')}</div>
            <div><strong>Stages:</strong> {selectedProfileInfo.stages.map((s) => s.name).join(' → ')}</div>
          </div>

          <div className="flex justify-center gap-4 pt-4">
            <button
              type="button"
              onClick={() => setStep(4)}
              className="px-4 py-2.5 text-[13px] text-graphite border border-warm-mist rounded-btn hover:text-ink"
            >
              Review Again
            </button>
            <button
              type="button"
              disabled={loading}
              onClick={handleStartExecution}
              className="px-6 py-2.5 text-[15px] font-medium text-white rounded-input transition-opacity hover:opacity-90 disabled:opacity-50"
              style={{ background: '#016a71' }}
            >
              {loading ? 'Launching Scan…' : 'Start Assessment Now 🚀'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
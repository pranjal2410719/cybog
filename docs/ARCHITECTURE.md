# CYBOG Architecture

## Canonical Orchestrator: `JobScheduler`

`JobScheduler` (in `cybog/workflow/scheduler.py`) is the single authoritative
pipeline orchestrator for the CYBOG security assessment platform. All pipeline
execution flows through it; there is no secondary orchestrator.

### How it works

- Targets enter the pipeline simultaneously via the subfinder discovery queue.
- Per-stage bounded `asyncio.Queue` instances enforce backpressure between stages.
- Per-stage `WorkerPool` instances (semaphore-limited) enforce concurrency limits.
- Targets advance independently: Target A may be in `dnsx` while Target B is
  still in `subfinder`.
- `httpx` and `naabu` run concurrently for the same target via `asyncio.gather`.
- A failure in one target never blocks or stops other targets (failure isolation).
- `AssessmentState` is persisted to disk after every job completion for crash
  safety and resumability.

### Pipeline graph

```
subfinder -> dnsx -> (httpx || naabu) -> katana -> ffuf -> nuclei
```

- Stage order (`STAGES_ORDER` in `cybog/workflow/scheduler.py`):
  `subfinder, dnsx, httpx, naabu, katana, ffuf, nuclei`.
- `httpx` and `naabu` are independent branches between `dnsx` and `katana`;
  `katana` waits for both to complete.
- Each stage enqueues its downstream stage(s) only after its own job completes,
  so ordering is enforced by queue topology, not a graph library.


### Public API surface (`cybog/workflow/__init__.py`)

```python
from cybog.workflow.scheduler import JobScheduler   # canonical orchestrator
from cybog.workflow.router   import PipelineRouter   # stage routing helper
from cybog.workflow.nodes    import run_stage_node   # individual stage runner
```

`JobScheduler` owns all queue management, worker pool coordination, stage
sequencing, and state persistence. Callers interact with it exclusively through
its public methods — no graph or state-machine framework mediates execution.

## Validation plane

Findings do not count as results until they pass validation. The validation
lifecycle is enforced by `ValidationStatus` transitions
(`cybog/models/finding.py`):

```
Finding (DISCOVERED)
   -> NEEDS_VALIDATION        (when a validator exists for the finding)
   -> AnalystTask created     (_ensure_analyst_task: exactly one per finding,
                               persisted in AssessmentState)
   -> BoundedAnalystQueue     (cybog/queue/analyst_queue.py; bounded queue
                               consumed by the scheduler's analyst workers)
   -> VALIDATING              (validator adapter runs against the live service)
   -> VALIDATED | FALSE_POSITIVE
```

- A finding with no configured validator is never guessed: it stays pending
  (`finding_without_validator_is_not_guessed` behavior) and blocks target
  completion until resolved or accepted.
- `VALIDATED` and `FALSE_POSITIVE` are terminal states; evidence attached
  during validation persists with the finding.
- Analyst tasks are idempotent across resume and duplicate scheduler runs —
  exactly one task per finding, executed once.

---

## Out of Scope: `langgraph`, `graph.py`, `WorkflowState`

The CYBOG platform **does not use** LangGraph, LangChain, or any graph-based
workflow library.

The following artifacts were removed during Phase 1 cleanup because they
referenced a module that never existed:

| Removed artifact | Location | Reason |
|---|---|---|
| `from cybog.workflow.graph import WorkflowState` | `cybog/workflow/nodes.py` (TYPE_CHECKING block) | `cybog/workflow/graph.py` does not exist |
| `cybog/workflow/graph.py` | — | Never created; LangGraph dependency removed from `setup.py` and `requirements.txt` |
| `langgraph>=0.1.0` | `setup.py`, `requirements.txt`, `cybog.egg-info/requires.txt` | Removed — not a runtime dependency |

Any residual references to `langgraph`, `langchain-core`, `graph.py`, or
`WorkflowState` in documentation or comments are stale and should be removed.

### What replaced graph-based orchestration

The hand-written `JobScheduler` class provides:

- **Deterministic stage ordering** — explicit queue-to-queue hand-off, no
  dynamic graph traversal.
- **Fine-grained concurrency control** — per-stage semaphores rather than
  graph-edge fan-out.
- **Crash-safe state** — atomic JSON save after every job, no checkpoint
  manager required.
- **No external orchestration dependency** — pure `asyncio`, no LangGraph
  runtime.

---

## Phase 2 freeze

This architecture is **frozen for Phase 2**:

- `JobScheduler` remains the sole pipeline orchestrator; no graph-based or
  state-machine framework will be introduced.
- The stage order and the parallel `httpx`/`naabu` branch are fixed.
- The validation plane (Finding -> NEEDS_VALIDATION -> AnalystTask ->
  BoundedAnalystQueue -> VALIDATING -> VALIDATED/FALSE_POSITIVE) is the only
  finding-lifecycle path.
- `langgraph`, `langchain-core`, `cybog/workflow/graph.py`, and `WorkflowState`
  are NOT used anywhere in this codebase and remain out of scope.

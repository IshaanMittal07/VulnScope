# SecureAssess — Implementation Guide

Follow the phases in order. Each phase has a goal, a prompt to give Claude Code, what to check
yourself, and a commit message. Don't move on until the "Done when" checks pass.

## How to work with Claude Code (read once)
- **One phase per session.** Start a fresh session for each phase so context stays focused.
- **Plan first.** Every prompt below asks for a plan before code. Read it, question anything unclear, then approve.
- **Review every diff.** You must be able to explain every file in interviews. If something is unclear,
  ask: "Explain what this file does and why, as if I'm new to this."
- **Commit after each phase** so you can always roll back.
- **If stuck for more than two attempts** on the same error, ask Claude Code to stop, summarize what it
  tried, and list hypotheses before trying again.

---

## Phase 0 — Set up your machine (you do this, ~1 hour)
1. Install: Git, Docker (Docker Desktop on Windows/macOS, Docker Engine on Linux), Python 3.12,
   Node.js LTS, `uv` (Python package manager), Make (Windows: use WSL2, strongly recommended).
2. Install Ollama and pull a model that fits your RAM, for example `ollama pull qwen2.5:7b`
   (roughly 8 GB+ RAM) or a 3B model if you have less. Test it: `ollama run qwen2.5:7b "hello"`.
3. Request a free NVD API key at nvd.nist.gov (arrives by email).
4. Create the repo:
   ```
   mkdir secureassess && cd secureassess
   git init
   mkdir docs
   ```
   Put `CLAUDE.md` in the root and this file at `docs/IMPLEMENTATION_GUIDE.md`.
5. Create an empty GitHub repository and connect it (`git remote add origin ...`).

**Done when:** Docker runs `docker run hello-world`, Ollama answers a prompt, both files are in place.

---

## Phase 1 — Scaffold the file structure and skeleton services
**Goal:** The full folder structure exists and a minimal stack starts with one command.

**Prompt:**
> Read CLAUDE.md and the Phase 1 section of docs/IMPLEMENTATION_GUIDE.md. Propose a plan, then:
> create the full directory structure from CLAUDE.md with placeholder modules (docstrings describing
> each module's purpose, no logic yet); set up backend/pyproject.toml with uv, ruff, mypy, pytest;
> create a FastAPI app with GET /health; create docker-compose.yml with api, db (postgres), redis,
> and frontend (Vite React TS hello page) only; create .env.example, .gitignore, Makefile with
> up/down/test/lint targets; add a basic README. Add one passing test for /health.

**Done when:**
- `make up` starts everything; http://localhost:8000/health returns `{"status": "ok"}`.
- The frontend page loads.
- `make test` and `make lint` pass.

**Commit:** `feat: scaffold project structure and skeleton services`

---

## Phase 2 — Database models and migrations
**Goal:** All core tables exist.

**Prompt:**
> Phase 2. Implement SQLAlchemy 2.0 models in backend/app/models for Target, OwnershipVerification,
> Scan, ScanJob, Finding, PolicyMapping, ProtectionPlan, AuditRun, AuditFinding, PatchLog, and CveCache,
> with the pipeline state enum from CLAUDE.md. Set up Alembic and create the initial migration.
> Add a `make migrate` target. Add Pydantic schemas for each. Propose the schema (fields and
> relationships) before writing code.

**Done when:**
- `make migrate` creates all tables (check with `docker compose exec db psql -U ... -c '\dt'`).
- Unit tests create and query each model against a test database.
- You can explain every relationship in the schema.

**Commit:** `feat: add database models and initial migration`

---

## Phase 3 — Job queue and pipeline skeleton
**Goal:** A request creates a scan that moves through all states using fake steps.

**Prompt:**
> Phase 3. Add an RQ worker service to docker-compose. Implement workers/tasks.py with run_scan,
> run_analysis, run_plan, run_audit as stubs that sleep briefly and advance the pipeline state.
> Add API endpoints: POST /targets, POST /scans (start pipeline), GET /scans/{id} (status and state).
> Failures must set state=failed with an error message. Add integration tests using RQ's synchronous
> mode.

**Done when:** Creating a scan via the API and polling it shows it advancing to `complete`.

**Commit:** `feat: add job queue and pipeline state machine`

---

## Phase 4 — Lab targets and ownership verification
**Goal:** Scans are blocked unless the target is verified or a lab target.

**Prompt:**
> Phase 4. Create docker-compose.lab.yml with OWASP Juice Shop and DVWA on an internal Docker network
> shared with the worker. Add `make lab`. Implement verification/: DNS TXT verification (random token,
> record `_secureassess.<domain>`), HTTP token verification (/.well-known/secureassess-verify.txt),
> and lab verification (only juice-shop and dvwa hostnames, only when LAB_MODE=true). Tokens must be
> generated with `secrets`, expire after 24 hours, and be single-use. POST /scans must return 403 for
> unverified targets. Write tests proving unverified targets cannot be scanned, including edge cases
> like expired tokens and hostnames that merely contain "juice-shop".

**Done when:**
- An unverified target returns 403.
- `juice-shop` works in lab mode and fails with LAB_MODE=false.
- You can explain why verification exists (legal authorization) in one sentence.

**Commit:** `feat: add ownership verification and lab targets`

---

## Phase 5 — Scanner adapters (one at a time)
**Goal:** Real scans run against lab targets and produce raw findings.

Do this phase in five sub-sessions, in this order: **Nmap → testssl.sh → Nuclei → ZAP → Trivy.**

**Prompt (repeat per scanner, replacing NAME):**
> Phase 5, scanner: NAME. First, if it's not done yet, create Dockerfile.worker with the scanner tools
> installed at pinned versions. Implement scanners/NAME.py following the Scanner base class. Run it
> once against the lab target, save the raw output to tests/fixtures/, and write parser tests against
> that fixture. Enforce timeouts and never pass user input through a shell (use argument lists).
> Register it in scanners/registry.py for the right service types. Wire it into run_scan.

Notes:
- ZAP runs as its own service in daemon mode; the adapter talks to its API over the internal network.
  Use the baseline (passive) scan by default.
- Trivy scans images or repos rather than network services; register it for the "repo/container" type.

**Done when:** A full scan of Juice Shop stores raw findings from all five scanners, and parser tests
pass without network access.

**Commit (per scanner):** `feat: add NAME scanner adapter`

---

## Phase 6 — Normalization, deduplication, and CVE enrichment
**Goal:** Raw scanner output becomes clean, ranked findings.

**Prompt:**
> Phase 6. Implement analysis/: normalize RawFindings from all scanners into one Finding shape
> (title, description, evidence, affected asset, source scanner, CVE IDs, CWE IDs, severity).
> Deduplicate findings reported by multiple scanners. Implement an NVD API 2.0 client with the API
> key from config, respecting rate limits, caching responses in CveCache. Compute severity from CVSS
> where available, otherwise map scanner severity. Wire into run_analysis. Tests must mock NVD.

**Done when:** The Juice Shop scan produces a deduplicated, severity-sorted findings list, and a
second run uses the cache instead of calling NVD.

**Commit:** `feat: add finding normalization and CVE enrichment`

---

## Phase 7 — Policy mapping
**Goal:** Each finding is linked to the policies it relates to.

**Prompt:**
> Phase 7. Create YAML mapping files in policies/data mapping CWE IDs and finding categories to
> OWASP Top 10, NIST 800-53 controls, CIS Controls, PCI DSS requirements, and PIPEDA principles.
> Reference control IDs and short descriptions in your own words; do not copy text from the standards.
> Implement selector.py (data type -> frameworks, e.g. payment data adds PCI DSS, Canadian personal
> data adds PIPEDA) and mapper.py. Add tests covering each framework.

**Done when:** Findings show mapped controls, and changing the target's data type changes which
frameworks appear. Spot-check 5 mappings yourself against the official standards.

**Commit:** `feat: add security policy mapping`

---

## Phase 8 — LLM layer
**Goal:** A swappable LLM provider generates explanations and prioritization.

**Prompt:**
> Phase 8. Implement llm/base.py (LLMProvider protocol with complete_json(prompt, schema)),
> llm/ollama.py (Ollama HTTP API, model from config), and llm/fake.py for tests. All outputs are
> validated with Pydantic; retry once on invalid JSON, then fail gracefully. Add an ollama service to
> docker-compose (or document connecting to host Ollama). Write prompt templates in llm/prompts/ for:
> plain-language finding explanations and fix prioritization. Treat scanner output inside prompts as
> untrusted data and delimit it clearly.

**Done when:** Findings get readable explanations from your local model, and all tests run with the
fake provider.

**Commit:** `feat: add provider-agnostic LLM layer`

---

## Phase 9 — Protection plan generator
**Goal:** Findings produce a PlanSpec and rendered, working crypto code.

**Prompt:**
> Phase 9. Implement crypto_plan/: spec.py (PlanSpec with only allowed options as enums), planner.py
> (rule-based selection from findings and data type; the LLM may only suggest spec changes, which are
> validated against the enums), templates for AEAD with Tink and PyNaCl, Argon2id password hashing,
> envelope encryption with OpenBao transit, and a hardened TLS config. Add an openbao service in dev
> mode to docker-compose. renderer.py renders templates from the spec. Explain each crypto choice in
> docs/adr/. Add tests that rendered code imports and round-trips data correctly.

**Done when:** Juice Shop's findings produce a plan, the rendered code encrypts and decrypts correctly,
and you can explain why each algorithm was chosen and what a nonce is.

**Commit:** `feat: add protection plan generator and crypto templates`

---

## Phase 10 — Sandbox and audit checks
**Goal:** Generated code is audited in isolation.

**Prompt:**
> Phase 10. Build the sandbox container: non-root user, read-only root filesystem, tmpfs for /tmp,
> CPU and memory limits, attached only to an internal network with no internet access. Implement
> runner.py and checks/: static_analysis (Semgrep with custom rules in rules/semgrep/crypto.yml plus
> Bandit), wycheproof (run vectors for the algorithms in use; add scripts/fetch_wycheproof.sh and
> `make fetch-vectors`), and properties (Hypothesis: round-trip, single-bit-flip rejection, nonce
> uniqueness across many encryptions, identical error messages for all decryption failures).
> Results are JSON AuditFindings. IMPORTANT: create deliberately broken sample implementations in
> sandbox/tests (ECB mode, reused nonce, hardcoded key, leaky errors) and prove each check catches its bug.

**Done when:** Every deliberately broken sample is caught, the correctly rendered code passes,
and the sandbox has no internet access (verify it can't reach an external site).

**Commit:** `feat: add sandboxed crypto audit checks`

---

## Phase 11 — Test-and-fix loop
**Goal:** Findings feed back into the planner until clean or out of iterations.

**Prompt:**
> Phase 11. Implement audit/: llm_review.py (adversarial review of code + spec against a checklist:
> key storage, rotation, access scope, logging of secrets, missing authentication; returns validated
> JSON findings), fixer.py (maps findings to PlanSpec changes; LLM suggestions must pass spec
> validation), and loop.py (render → run full sandbox suite + LLM review → fix → repeat; stop at zero
> findings or 5 iterations; unresolved findings marked needs_human_review; every change written to
> PatchLog). Wire into run_audit. Test the loop by seeding a spec with a known weakness and asserting
> it's fixed and logged.

**Done when:** A seeded weakness is detected, fixed, and logged, and the loop never exceeds 5 iterations.

**Commit:** `feat: add audit test-and-fix loop`

---

## Phase 12 — Reports
**Goal:** A complete, readable report.

**Prompt:**
> Phase 12. Implement reports/builder.py producing HTML and JSON: executive summary, findings by
> severity with explanations and mapped policies, protection plan with rationale, audit history
> (iterations, findings, patches), unresolved items, and a limitations section stating that passing
> the audit is not proof of security and recommending human review. Add GET /reports/{scan_id}.

**Done when:** You can hand the Juice Shop report to someone non-technical and they understand the top risks.

**Commit:** `feat: add report generation`

---

## Phase 13 — Frontend
**Goal:** A clean UI for the full flow.

**Prompt:**
> Phase 13. Build the React pages: NewTarget (target + data type), Verify (shows token and
> instructions, checks status), ScanProgress (polls pipeline state), Findings (filter by severity),
> Plan, Audit (iteration timeline), Report (view + download JSON). Keep the design clean and
> accessible, with loading and error states on every page. Propose the page flow before coding.

**Done when:** You can go from entering Juice Shop to viewing the final report entirely in the browser.

**Commit:** `feat: add frontend for full pipeline`

---

## Phase 14 — CI, benchmarks, and hardening
**Goal:** Automated quality checks and resume-ready metrics.

**Prompt:**
> Phase 14. Add .github/workflows/ci.yml running lint, mypy, backend tests, sandbox tests, and a
> frontend build. Implement scripts/benchmark_lab.py that runs the full pipeline against Juice Shop
> and DVWA and records: findings detected, severity breakdown, audit iterations, issues fixed, and
> runtime. Write docs/threat-model.md covering how this tool itself could be abused or attacked
> and the mitigations in place. Review the codebase for secrets in code, shell injection, and
> missing timeouts.

**Done when:** CI is green on GitHub, and you have benchmark numbers written down.

**Commit:** `chore: add CI, benchmarks, and threat model`

---

## Phase 15 — Documentation and launch
**Goal:** Anyone can understand and run it in minutes.

**You do (with Claude Code's help):**
1. README: one-paragraph pitch, architecture diagram, quickstart (`make up && make lab`), screenshots,
   benchmark results, ethics/authorization notice, limitations.
2. docs/architecture.md with a pipeline diagram (Mermaid works on GitHub).
3. Record a 2–3 minute demo video of scanning Juice Shop end to end.
4. Tag a release (`v1.0.0`).
5. Write resume bullets using your real benchmark numbers.

---

## Stretch goals (after v1)
- Atheris fuzzing in the sandbox.
- CLI mode for use in CI pipelines.
- PDF report export.
- Scan comparison over time ("what changed since last scan").
- Support for another service type (e.g. databases via configuration checks).

# VulnScope

A self-hosted security assessment platform. You give it a service you own and the kind of data
it handles. It scans the service with established open-source tools, maps the findings to CVEs and
security frameworks, and generates a protection plan built only from vetted cryptographic
primitives. The generated code then goes through an automated audit loop before the final report.

> **Status:** early development (Phase 1, scaffold). See [docs/IMPLEMENTATION_GUIDE.md](docs/IMPLEMENTATION_GUIDE.md).

> **Authorization:** only scan systems you own or have written permission to test. VulnScope
> refuses to scan a target until you verify ownership of it.

## Quickstart

Requires Docker (with Compose), [uv](https://docs.astral.sh/uv/), and Make.

```bash
make up        # creates .env from .env.example on first run, then builds and starts the stack
```

| Service  | URL                          |
|----------|------------------------------|
| API      | http://localhost:8000/health |
| API docs | http://localhost:8000/docs   |
| Frontend | http://localhost:5173        |

```bash
make test      # backend tests
make lint      # ruff + mypy
make down      # stop everything
```

## Layout

```
backend/            FastAPI app (Python 3.12, uv)
  app/api/          HTTP routes
  app/models/       SQLAlchemy models
  app/schemas/      Pydantic schemas
  app/workers/      Background pipeline jobs
  app/verification/ Target ownership verification
  app/scanners/     Nmap, testssl.sh, Nuclei, ZAP, Trivy adapters
  app/analysis/     Normalization, dedup, CVE enrichment
  app/policies/     OWASP / NIST / CIS / PCI DSS / PIPEDA mapping
  app/llm/          Provider-agnostic LLM interface (Ollama by default)
  app/crypto_plan/  Protection plan generator (vetted primitives only)
  app/audit/        Test-and-fix loop
  app/reports/      HTML/JSON report builder
sandbox/            Isolated container for auditing generated crypto code
frontend/           React + TypeScript (Vite)
scripts/            Benchmarks and helper scripts
docs/               Implementation guide and ADRs
```

## Tech stack

FastAPI, PostgreSQL, Redis, React, and Docker Compose. Everything is free and open source; the LLM
runs locally through Ollama.

## Limitations

Passing VulnScope's audit does not prove a system is secure. Have a human review the results before
using anything it produces in production.

# VulnScope

A self-hosted security assessment platform. You give it a service you own and the kind of data
it handles. It scans the service with established open-source tools, maps the findings to CVEs and
security frameworks, and generates a protection plan built only from vetted cryptographic
primitives. The generated code then goes through an automated audit loop before the final report.

> **Status:** early development (Phase 2, database models and migrations). See [docs/IMPLEMENTATION_GUIDE.md](docs/IMPLEMENTATION_GUIDE.md).

> **Authorization:** only scan systems you own or have written permission to test. VulnScope
> refuses to scan a target until you verify ownership of it.

## Quickstart

Requires Docker (with Compose), [uv](https://docs.astral.sh/uv/), and Make.

```bash
make up        # creates .env from .env.example on first run, then builds and starts the stack
               # (the api container applies database migrations before it starts)
make seed      # optional: add sample Juice Shop data to browse
```

| Service  | URL                          |
|----------|------------------------------|
| API      | http://localhost:8000/health |
| API docs | http://localhost:8000/docs   |
| Frontend | http://localhost:5173        |

```bash
make test      # backend tests (against a separate <db>_test database)
make lint      # ruff + mypy
make psql      # SQL shell on the dev database
make migrate   # apply new migrations without restarting the api
make down      # stop everything
make help      # list every target
```

### Troubleshooting

- **`password authentication failed for user "vulnscope"`**: Postgres reads `POSTGRES_*` from `.env`
  only when its data volume is first created. If the volume is older than your current `.env`, run
  `make reset-db`. It deletes all dev data and rebuilds the database from the migrations.
- **`ports are not available`**: something else is already using 5432, 6379, 8000, or 5173. Stop it,
  or run `make down` if it's an older VulnScope stack.

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

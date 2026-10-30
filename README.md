# VulnScope

A self-hosted security assessment platform. You give it a service you own and the kind of data
it handles. It scans the service with established open-source tools, maps the findings to CVEs and
security frameworks, and generates a protection plan built only from vetted cryptographic
primitives. The generated code then goes through an automated audit loop before the final report.

> **Status:** early development (Phase 4, lab targets and ownership verification; the pipeline
> stages are still stubs). See [docs/IMPLEMENTATION_GUIDE.md](docs/IMPLEMENTATION_GUIDE.md).

> **Authorization:** only scan systems you own or have written permission to test. VulnScope
> refuses to scan a target until you verify ownership of it.

## Quickstart

Requires Docker (with Compose), [uv](https://docs.astral.sh/uv/), and Make.

```bash
make up        # creates .env from .env.example on first run, then builds and starts the stack
               # (the api container applies database migrations before it starts)
make seed      # optional: add sample Juice Shop data to browse
make lab       # optional: also start the lab targets (Juice Shop, DVWA) on an internal network
```

The lab targets are deliberately vulnerable apps. They run on an internal Docker network with no
internet access and no ports published on your machine. Of VulnScope's own services, only the
worker joins that network and can reach them, at `http://juice-shop:3000` and `http://dvwa`; the
lab apps can also reach each other. On a native Linux Docker host, the host itself may still reach
container IPs directly (Docker Desktop, used on Windows and macOS, doesn't allow this).
DVWA's database is kept in memory, so `make lab` creates its tables whenever it starts empty, and
leaves them alone otherwise (DVWA's default login is `admin` / `password`). `make lab-reset-dvwa`
wipes and recreates it.

| Service  | URL                          |
|----------|------------------------------|
| API      | http://localhost:8000/health |
| API docs | http://localhost:8000/docs   |
| Frontend | http://localhost:5173        |
| Worker   | no URL; `docker compose logs -f worker` shows the pipeline jobs it runs |

### Prove ownership, then scan

VulnScope won't scan a target until you prove you control it: `POST /scans` answers **403** until
then. Each passed verification authorizes **one** scan and expires 24 hours after it was created.

| Method | How you prove it |
|--------|------------------|
| `dns_txt` | a TXT record at `_vulnscope.<domain>` containing the token |
| `http_token` | the token served at `/.well-known/vulnscope-verify.txt` on the target (public addresses only) |
| `lab` | no token: only the lab hosts `juice-shop` and `dvwa`, and only while `LAB_MODE=true` (as in `.env.example`) |

Try it with the lab target. A worker runs the stages in the background, so repeating the last
command shows the state advance `queued -> scanning -> analyzing -> planning -> auditing -> reporting -> complete`.

```bash
curl -s -X POST http://localhost:8000/targets -H 'Content-Type: application/json' \
  -d '{"name": "Juice Shop (lab)", "target_type": "url", "value": "http://juice-shop:3000", "data_types": ["personal"]}'
# copy the "id" into <target-id>, then ask for a lab verification:
curl -s -X POST http://localhost:8000/targets/<target-id>/verifications -H 'Content-Type: application/json' \
  -d '{"method": "lab"}'
# copy the verification's "id" into <verification-id>, then check it ("status": "verified"):
curl -s -X POST http://localhost:8000/targets/<target-id>/verifications/<verification-id>/check
# now the scan is allowed (202); copy its "id" into <scan-id>, then repeat:
curl -s -X POST http://localhost:8000/scans -H 'Content-Type: application/json' \
  -d '{"target_id": "<target-id>"}'
curl -s http://localhost:8000/scans/<scan-id>
```

For `dns_txt` and `http_token`, the response to the second command includes the token and
`instructions` saying exactly where to publish it; run the check once it's in place. A failed
check answers 409 with the reason, and you can retry until the verification expires.

The pipeline stages are still stubs that only wait (`PIPELINE_STEP_DELAY_SECONDS`, default 1s) and
never contact the target; real scanners arrive in Phase 5.

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

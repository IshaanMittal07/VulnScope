# Project: Self-Hosted Security Assessment Platform

## Overview
A self-hosted web app (distributed via Docker Compose, accessed at localhost) that:
1. Takes a service the user wants to secure (URL, IP, domain, or repo) plus the type of data it handles.
2. Runs a vulnerability assessment using established open-source scanners.
3. Maps findings to CVEs, CVSS severity, and security policies/frameworks.
4. Generates a protection plan using **vetted cryptographic primitives only** (no custom ciphers or schemes).
5. Runs an automated test-and-fix loop that audits the generated crypto implementation and patches issues.
6. Produces a final report: findings, relevant policies, and the approved crypto config and code.

This is a portfolio/resume project. Prioritize a small, reliable, well-tested scope over breadth.

## Hard constraints
- **Everything must be free.** No paid services or APIs.
- **Never invent cryptography.** Use libsodium, Google Tink, or Python `cryptography`. Allowed choices include AES-256-GCM, XChaCha20-Poly1305, Argon2id (passwords), TLS 1.3.
- **Authorization first.** No scan runs until target ownership is verified (e.g. DNS TXT record or file-on-server token). Default dev/test targets are local only.
- No exploit code. Scanning and auditing only.

## Tech stack (all free)
- Backend: Python, FastAPI
- Jobs: Celery or RQ with Redis
- Database: PostgreSQL
- Frontend: React
- Deployment: Docker Compose; each scanner runs in its own isolated container
- Scanners: Nmap, Nuclei, testssl.sh (or sslyze), OWASP ZAP, Trivy; OpenVAS/Greenbone Community Edition optional
- Vulnerability data: NVD API (free key)
- Policy frameworks: OWASP Top 10 / ASVS, NIST SP 800-53 / CSF, CIS Benchmarks, PCI DSS, PIPEDA
- Key management: OpenBao (open-source Vault fork) in Docker
- LLM: local model via Ollama (e.g. Llama or Qwen). Build a provider-agnostic LLM interface so other providers can be swapped in.
- Crypto testing: Semgrep Community Edition, Bandit, Project Wycheproof test vectors, Hypothesis (property tests), AFL++ (fuzzing)
- Test targets: OWASP Juice Shop and DVWA, running locally in Docker
- CI: GitHub Actions

## Pipeline stages
1. **Target intake** – collect target + data type; verify ownership before proceeding.
2. **Automated scanning** – queue scanner jobs by service type; collect JSON/XML output.
3. **Analysis and mapping** – normalize and deduplicate findings, enrich with CVE/CVSS, tag with violated policies (framework choice depends on data type). LLM writes plain-language explanations and prioritizes fixes.
4. **Protection plan** – select standard components based on findings; output a config plus working implementation code.
5. **Test-and-fix loop**:
   - Static analysis (Semgrep crypto rules, Bandit): hardcoded keys, ECB, non-CSPRNG randomness, disabled cert verification, keys in logs.
   - Wycheproof test vectors: tampered ciphertexts must be rejected.
   - Property tests / fuzzing: round-trip correctness, bit-flip rejection, no nonce reuse under one key, no informative decryption errors.
   - LLM adversarial review against a checklist; returns structured JSON findings.
   - Findings go back to the generator for patching; every change is logged.
   - Re-run the FULL suite each iteration. Max 5 iterations; unresolved items are flagged for human review.
6. **Report** – findings, policies, fix history, final config. State clearly that passing the suite is not proof of security and recommend human review before production use.

## Suggested build order (MVP first)
1. Docker Compose skeleton: FastAPI, Postgres, Redis, worker, Juice Shop target.
2. Single scan path for web services: Nmap + testssl.sh + Nuclei, results stored in DB.
3. Normalization, CVE enrichment, OWASP/NIST mapping, basic report page.
4. Ownership verification flow.
5. Protection plan generator + test-and-fix loop.
6. React UI polish, README with architecture diagram, demo video, CI.

## Success metrics to track (for the resume)
- Detection rate against known vulnerabilities in Juice Shop/DVWA.
- Issues caught and fixed by the test-and-fix loop, and iterations needed.

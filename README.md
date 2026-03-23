# RepolyzeAI

**Paste your repo. Know your risks. Ship with confidence.**

RepolyzeAI is an AI-powered security audit platform that scans GitHub repositories for code vulnerabilities, AI agent safety issues, and MCP server security. It combines 6 static scanners with a 3-agent ADK pipeline (following Google's [LLM Auditor](https://github.com/google/adk-samples/tree/main/python/agents/llm-auditor) pattern) that verifies findings against actual source code, searches for CVE context, and generates specific code fixes.

## What Makes This Different

Most security tools do ONE thing. RepolyzeAI runs **9 analysis stages** in a single scan:

### Static Scanners (1-6)

| Scanner | What It Does |
|---------|-------------|
| **Semgrep** | Static analysis across 30+ languages (SQL injection, XSS, auth issues) |
| **Secret Scanner** | Detects hardcoded API keys, tokens, passwords (TruffleHog + regex) |
| **Dependency Scanner** | Checks pip/npm packages against known CVEs (pip-audit, npm audit) |
| **Agent Safety** | Auto-detects LangChain, CrewAI, ADK, OpenAI Agents; audits for missing guardrails |
| **MCP Auditor** | Analyzes MCP tool definitions for shell execution, file access, missing validation |
| **Red-Team Engine** | 90+ adversarial probes across 8 attack categories (OWASP LLM Top 10) |

### ADK AI Agents (7-9)

Built with [Google ADK](https://google.github.io/adk-docs), following the [LLM Auditor](https://github.com/google/adk-samples/tree/main/python/agents/llm-auditor) Critic/Reviser pattern:

| Agent | What It Does |
|-------|-------------|
| **SecurityCritic** | Reads source code via tools, verifies each finding, removes false positives |
| **CVEResearcher** | Uses Google Search to find CVE details, known exploits, security advisories |
| **RemediationAdvisor** | Generates specific code-level fixes with before/after examples |

The Critic agent alone reduced false positives by ~9% on our test scans by reading the actual source code and verifying each finding in context.

### Self-Improving Detection

Inspired by [Karpathy's autoresearch](https://github.com/karpathy/autoresearch): a loop that modifies detection rules, evaluates against a test suite of 40 vulnerable + safe code samples, and keeps only improvements. Current score: **570/500** (100% detection, 0 false positives).

## Quick Start

### Option 1: Demo Mode (no external deps)

```bash
git clone https://github.com/theaayushstha1/repolyze-ai.git
cd repolyze-ai

# Backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pip install semgrep google-adk google-genai psycopg2-binary
python demo.py
# http://localhost:8000

# Frontend (new terminal)
cd frontend && npm install && npx next dev
# http://localhost:3000
```

### Option 2: Full Stack (with Postgres persistence)

```bash
# Copy env and add your keys
cp .env.example .env
# Edit .env: set GEMINI_API_KEY

# Start Postgres + Redis
docker compose up -d redis postgres

# Backend
cd backend && source .venv/bin/activate && python demo.py

# Frontend
cd frontend && npx next dev
```

Open http://localhost:3000, paste any public GitHub URL, hit Scan.

## Architecture

```
User pastes GitHub URL
         │
    Next.js 16 Frontend (localhost:3000)
         │
    FastAPI Backend (localhost:8000)
         │
    ┌────────────────────────────────────────┐
    │         Scan Orchestrator              │
    │  1. Clone repo (git clone --depth 1)   │
    │  2. Detect languages + AI frameworks   │
    │  3. Run 6 static scanners in parallel  │
    │  4. Run 3 ADK agents sequentially      │
    │  5. Aggregate + grade + generate PDF   │
    └────────────────────────────────────────┘
         │                    │
    ┌────┴────┐    ┌─────────┴──────────┐
    │ Static  │    │   ADK Agents       │
    │ Semgrep │    │ SecurityCritic     │
    │ Secrets │    │   → reads code     │
    │ Deps    │    │   → verifies       │
    │ Agent   │    │ CVEResearcher      │
    │ MCP     │    │   → google search  │
    │ RedTeam │    │ RemediationAdvisor │
    └─────────┘    │   → generates fixes│
                   └────────────────────┘
         │
    PostgreSQL (Docker) ← findings persist
         │
    PDF Report (ReportLab)
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Next.js 16, Tailwind CSS v4, shadcn/ui |
| Backend | Python FastAPI, Celery, Redis |
| AI Agents | Google ADK 1.27+ (LLM Auditor pattern) |
| AI Model | Gemini 2.5 Flash |
| Database | PostgreSQL 16 (Docker) / Supabase |
| Scanning | Semgrep, TruffleHog, pip-audit, npm audit |
| PDF | ReportLab |
| Deploy | Vercel + Cloud Run + Vertex AI |

## Project Structure

```
repolyze-ai/
├── frontend/              # Next.js 16 (home, dashboard, scan detail)
├── backend/
│   ├── app/
│   │   ├── api/           # FastAPI routes (scans, reports, health, A2A)
│   │   ├── services/      # Scan engines + ADK pipeline
│   │   │   ├── adk_agents/    # 3 ADK agents (critic, researcher, remediator)
│   │   │   ├── real_scan_service.py  # Main scan orchestrator
│   │   │   ├── secret_scanner.py
│   │   │   ├── dependency_scanner.py
│   │   │   ├── redteam_engine.py
│   │   │   └── pdf_generator.py
│   │   ├── db/            # PostgreSQL + Supabase layers
│   │   └── models/        # Pydantic schemas
│   ├── tests/             # 31 tests
│   └── demo.py            # Standalone server (no external deps)
├── agents/                # ADK agent definitions + red-team probes
│   └── agent_safety/
│       ├── probes/        # 90+ adversarial YAML probes
│       └── red_team/      # Attack strategies (Crescendo, TAP, Skeleton Key)
├── autoresearch/          # Self-improving detection rules
│   ├── scan_rules.py      # Mutable rules (31 patterns)
│   ├── evaluate.py        # Fixed test harness (40 samples)
│   └── program.md         # Loop instructions
├── supabase/              # Database migrations
├── docker-compose.yml     # Postgres 16 + Redis 7
└── docs/PRD.md            # Full product requirements
```

## API

```
POST /api/scans                              # Start scan
GET  /api/scans/{id}                         # Get status + results
GET  /api/scans/{id}/findings                # Get all findings
GET  /api/scans/{id}/agent-findings          # Agent safety findings only
GET  /api/scans/{id}/reports/latest/download # Download PDF report
GET  /api/dashboard/scans                    # All scan history
GET  /api/health                             # Health check
GET  /.well-known/agent.json                 # A2A agent discovery
```

Full Swagger docs: http://localhost:8000/docs

## Testing

```bash
# Backend tests (31 passing)
cd backend && source .venv/bin/activate
python -m pytest tests/ -v

# Autoresearch evaluation (score: 570)
cd autoresearch && python evaluate.py
```

## Inspiration

Built on the shoulders of:

- [Google ADK LLM Auditor](https://github.com/google/adk-samples/tree/main/python/agents/llm-auditor) — Multi-agent Critic/Reviser pattern
- [PromptFoo](https://github.com/promptfoo/promptfoo) (17.6k stars) — YAML red-team config, LLM-as-judge
- [Garak](https://github.com/NVIDIA/garak) (7.3k stars) — 100+ attack probes, plugin architecture
- [Semgrep](https://github.com/semgrep/semgrep) (13.4k stars) — Pattern-based static analysis
- [PyRIT](https://github.com/Azure/PyRIT) (1.5k stars) — Multi-turn attack orchestration
- [Karpathy's autoresearch](https://github.com/karpathy/autoresearch) — Self-improving experiment loop

## License

MIT

## Author

Built by [Aayush Shrestha](https://www.theaayushstha.com/) — [aashr3@morgan.edu](mailto:aashr3@morgan.edu)

# RepolyzeAI — Project Instructions

## Project Overview

RepolyzeAI is a universal, AI-powered security audit platform. Users paste a GitHub repo URL and receive a comprehensive security report covering code vulnerabilities, AI agent safety, and MCP server security.

**Key docs**: `docs/PRD.md` contains the full product requirements document.

## Memory System

**CRITICAL**: At the start of every session, read ALL memory files:
```
memory/user.md        — Who Aayush is, background, communication style
memory/decisions.md   — Architecture choices and what's connected vs not
memory/preferences.md — Coding style, testing, how to run locally
memory/people.md      — Collaborators and stakeholders
```

At the end of every session (or when significant decisions are made), update the relevant memory files:
- **decisions.md** — New architectural or technical decisions
- **preferences.md** — New coding or workflow preferences learned
- **user.md** — New context about the user
- **people.md** — New collaborators or stakeholders

## Tech Stack

- **Frontend**: Next.js 16 (App Router) + Tailwind CSS v4 + shadcn/ui
- **Backend**: Python FastAPI + Celery + Redis
- **Agents**: Google ADK + A2A protocol
- **Database**: Supabase PostgreSQL
- **Auth**: Supabase Auth + GitHub OAuth
- **PDF**: ReportLab (server-side)
- **Scanning**: Semgrep, TruffleHog, pip-audit, npm audit, custom regex
- **AI**: Gemini 2.5 Flash/Pro via ADK
- **Deploy**: Vercel (frontend) + Cloud Run (backend) + Vertex AI (agents)

## Project Structure

```
repolyze-ai/
├── frontend/        # Next.js 16 + shadcn/ui (3 pages: home, dashboard, scan detail)
├── backend/         # Python FastAPI (demo.py for no-deps mode, app/main.py for production)
│   ├── app/
│   │   ├── api/     # Route handlers (scans, reports, health, a2a, demo_router)
│   │   ├── services/# Scan engines (real_scan_service, secret_scanner, dependency_scanner, redteam_engine, pdf_generator)
│   │   ├── db/      # 3-tier DB layer (scan_repo, finding_repo, agent_finding_repo, report_repo)
│   │   └── models/  # Pydantic schemas (aligned with DB field names)
│   └── tests/       # 42 tests (test_scan_service, test_demo_api, test_db_layer)
├── agents/          # ADK + A2A agents (7 sub-agents)
├── autoresearch/    # Karpathy-style self-improving rules (scan_rules.py + evaluate.py)
├── memory/          # Persistent memory for Claude (this system)
├── supabase/        # Database migrations
└── docs/            # PRD, architecture docs
```

## Current State (Day 6 of 14-day MVP — 2026-03-23)

### What Works
- Full scan pipeline: clone -> detect -> 6 scanners -> aggregate -> PDF
- Demo mode runs without external deps (no Supabase/Redis/API keys needed)
- 3-tier storage fallback: Supabase -> PostgreSQL (Docker) -> in-memory
- Frontend with 3 pages, polling, findings table, PDF download
- Agent safety: detector, static analyzer, MCP auditor, 90 probes, 3 attack strategies
- 42 backend tests passing
- Autoresearch at 570 score (100% detection, 0 false positives)

### Storage Layer (3-tier fallback)
- **demo_store.py** routes all DB calls through: Supabase -> Postgres -> in-memory
- **db/client.py** uses service_role_key (bypasses RLS for backend writes)
- **db/scan_repo.py**, **finding_repo.py**, **agent_finding_repo.py**, **report_repo.py** all ready
- **supabase/migrations/** has 2 migrations (schema + anonymous scan policies)
- To activate Supabase: create project, paste real URL + keys in .env

### What's NOT Connected
- Supabase (placeholder creds, code is wired and ready)
- Redis / Celery workers
- Gemini API (has key, ADK pipeline skips gracefully)
- GitHub OAuth (no app)
- Semgrep / TruffleHog (not installed locally, uses regex fallback)
- Auth (returns fake user)
- SSE streaming (polling works, SSE sends once and closes)

## Coding Conventions

- **Immutability**: Always create new objects, never mutate
- **Small files**: 200-400 lines typical, 800 max
- **Error handling**: Handle errors explicitly at every level
- **Input validation**: Validate at system boundaries
- **Functions**: Keep under 50 lines, no deep nesting (>4 levels)
- **Commits**: Conventional commits (feat:, fix:, refactor:, etc.)
- **Testing**: TDD approach — write tests first, 80%+ coverage target

## Before Starting Work

1. Read memory files (memory/*.md)
2. Check `docs/PRD.md` for requirements
3. Run `cd backend && source .venv/bin/activate && python -m pytest tests/ -v` to verify nothing's broken
4. Start servers: backend `python demo.py`, frontend `cd frontend && npx next dev`

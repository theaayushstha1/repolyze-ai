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
│   │   ├── db/      # Supabase repository layer (placeholder)
│   │   └── models/  # Pydantic schemas
│   └── tests/       # 31 tests (test_scan_service.py, test_demo_api.py)
├── agents/          # ADK + A2A agents (7 sub-agents)
├── autoresearch/    # Karpathy-style self-improving rules (scan_rules.py + evaluate.py)
├── memory/          # Persistent memory for Claude (this system)
├── supabase/        # Database migrations
└── docs/            # PRD, architecture docs
```

## Current State (Day 5 of 14-day MVP)

### What Works
- Full scan pipeline: clone -> detect -> 6 scanners -> aggregate -> PDF
- Demo mode runs without external deps (no Supabase/Redis/API keys needed)
- Frontend with 3 pages, polling, findings table, PDF download
- 31 backend tests passing
- Autoresearch at 570 score (100% detection, 0 false positives)

### What's NOT Connected
- Supabase (placeholder creds)
- Redis / Celery workers
- Gemini API (no key)
- GitHub OAuth (no app)
- Semgrep / TruffleHog (not installed locally, uses regex fallback)
- Auth (returns fake user)
- SSE streaming (sends once and closes)

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

# RepolyzeAI — Project Instructions

## Project Overview

RepolyzeAI is a universal, AI-powered security audit platform. Users paste a GitHub repo URL and receive a comprehensive security report covering code vulnerabilities, AI agent safety, and MCP server security.

**Key docs**: `docs/PRD.md` contains the full product requirements document.

## Memory System

**CRITICAL**: At the start of every session, read the memory files:
```
~/.claude/projects/C--Users-aayus-Desktop-Start/memory/user.md
~/.claude/projects/C--Users-aayus-Desktop-Start/memory/decisions.md
~/.claude/projects/C--Users-aayus-Desktop-Start/memory/preferences.md
~/.claude/projects/C--Users-aayus-Desktop-Start/memory/people.md
```

At the end of every session (or when significant decisions are made), update the relevant memory files:
- **decisions.md** — New architectural or technical decisions
- **preferences.md** — New coding or workflow preferences learned
- **user.md** — New context about the user
- **people.md** — New collaborators or stakeholders

## Tech Stack

- **Frontend**: Next.js 15 (App Router) + Tailwind CSS + shadcn/ui
- **Backend**: Python FastAPI + Celery + Redis
- **Agents**: Google ADK + A2A protocol
- **Database**: Supabase PostgreSQL
- **Auth**: Supabase Auth + GitHub OAuth
- **PDF**: WeasyPrint (server-side)
- **Scanning**: Semgrep, Bandit, TruffleHog, osv-scanner
- **AI**: Gemini 2.5 Flash/Pro via ADK
- **Deploy**: Vercel (frontend) + Cloud Run (backend) + Vertex AI (agents)

## Project Structure

```
repolyze-ai/
├── frontend/     # Next.js 15
├── backend/      # Python FastAPI
├── agents/       # ADK + A2A agents
├── supabase/     # Database migrations
└── docs/         # PRD, architecture docs
```

## Coding Conventions

- **Immutability**: Always create new objects, never mutate
- **Small files**: 200-400 lines typical, 800 max
- **Error handling**: Handle errors explicitly at every level
- **Input validation**: Validate at system boundaries
- **Functions**: Keep under 50 lines, no deep nesting (>4 levels)
- **Commits**: Conventional commits (feat:, fix:, refactor:, etc.)
- **Testing**: TDD approach — write tests first, 80%+ coverage target

## Key Decisions (see decisions.md for full list)

- Auto-detect AI agents in repos (LangChain, CrewAI, ADK, OpenAI Agents SDK)
- Both static analysis AND live red-teaming from day 1
- YAML-based red-team config (PromptFoo-style)
- A2A protocol for independent agent communication
- Freemium pricing (5-10 free scans/month)

## Before Starting Work

1. Read memory files (above)
2. Check `docs/PRD.md` for requirements
3. Review the plan at `~/.claude/plans/shimmering-wondering-marshmallow.md`
4. Use planner agent for complex features
5. Use tdd-guide agent for new features
6. Use code-reviewer agent after writing code

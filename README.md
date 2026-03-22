# RepolyzeAI

**Paste your repo. Know your risks. Ship with confidence.**

RepolyzeAI is an AI-powered security audit platform that scans GitHub repositories for code vulnerabilities, AI agent safety issues, and MCP server security — all from a single URL.

## What Makes This Different

Most security tools do ONE thing. RepolyzeAI does THREE — in one scan:

| Capability | What It Does |
|---|---|
| **Code Security** | Semgrep static analysis across 30+ languages, dependency CVE scanning, secret detection |
| **AI Agent Safety** | Auto-detects LangChain, CrewAI, ADK, OpenAI Agents and audits for prompt injection, missing guardrails, data leakage |
| **MCP Server Audit** | Analyzes Model Context Protocol tool definitions for shell execution, file access, missing validation |

Plus a **self-improving autoresearch loop** (inspired by [Karpathy's autoresearch](https://github.com/karpathy/autoresearch)) that continuously improves detection rules.

## Quick Start

```bash
# Clone
git clone https://github.com/YOUR_USERNAME/repolyze-ai.git
cd repolyze-ai

# Frontend
cd frontend && npm install && npm run dev
# → http://localhost:3000

# Backend (demo mode — no database needed)
cd backend && pip install fastapi uvicorn pydantic-settings httpx reportlab
python demo.py
# → http://localhost:8000

# Open http://localhost:3000, paste a GitHub URL, click Scan
```

## Architecture

```
User → Next.js Frontend (Vercel)
         │
         ▼
    FastAPI Backend (Cloud Run)
         │
    Scan Orchestrator (ADK)
         │ A2A Protocol
    ┌────┼────────────┐
    │    │            │
Code   Agent        MCP
Audit  Safety      Audit
    │    │            │
    └────┼────────────┘
         ▼
    PDF Report Generator
```

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | Next.js 15, Tailwind CSS, shadcn/ui |
| Backend | Python FastAPI, Celery, Redis |
| Agents | Google ADK, A2A Protocol |
| Database | Supabase PostgreSQL |
| Scanning | Semgrep, custom agent/MCP analyzers |
| AI | Gemini 2.5 (via ADK) |
| PDF | ReportLab |
| Deploy | Vercel + Cloud Run + Vertex AI |

## Features

- **One-click scan** — paste a GitHub URL and go
- **Auto-detect AI agents** — LangChain, CrewAI, Google ADK, OpenAI Agents SDK
- **Auto-detect MCP servers** — finds and audits MCP tool definitions
- **90+ adversarial probes** — red-team AI agents with prompt injection, jailbreaks, data exfil
- **Professional PDF reports** — cover page, executive summary, findings, remediation
- **A-F safety grading** — clear, actionable security grades
- **OWASP LLM Top 10** — full coverage of AI-specific vulnerabilities
- **Self-improving rules** — autoresearch loop continuously improves detection

## Project Structure

```
repolyze-ai/
├── frontend/          # Next.js 15 web app
├── backend/           # FastAPI + Celery workers
├── agents/            # ADK agents + red-team probes
├── autoresearch/      # Self-improving detection rules
├── supabase/          # Database migrations
├── docs/              # PRD, study guide
└── docker-compose.yml # Local dev environment
```

## Autoresearch (Self-Improvement)

Inspired by [Karpathy's autoresearch](https://github.com/karpathy/autoresearch):

```bash
cd autoresearch
python evaluate.py  # Run evaluation against test suite
```

The agent modifies `scan_rules.py`, runs evaluation, keeps improvements, discards regressions. Current baseline: **445.0 detection score** (100% detection rate).

## API

```
POST /api/scans                           # Start scan
GET  /api/scans/{id}                      # Get status
GET  /api/scans/{id}/findings             # Get findings
GET  /api/scans/{id}/reports/latest/download  # Download PDF
```

Full API docs: `http://localhost:8000/docs`

## Inspiration

Built on the shoulders of giants:

- [PromptFoo](https://github.com/promptfoo/promptfoo) (17.6k ⭐) — YAML red-team config, LLM-as-judge
- [Garak](https://github.com/NVIDIA/garak) (7.3k ⭐) — 100+ attack probes, plugin architecture
- [Semgrep](https://github.com/semgrep/semgrep) (13.4k ⭐) — Pattern-based static analysis
- [PyRIT](https://github.com/Azure/PyRIT) (1.5k ⭐) — Multi-turn attack orchestration
- [Chain-Fox](https://github.com/Chain-Fox/Chain-Fox) — Blockchain security audit platform
- [Karpathy's autoresearch](https://github.com/karpathy/autoresearch) — Self-improving experiment loop

## License

MIT

## Author

Built by Aayush — [aashr3@morgan.edu](mailto:aashr3@morgan.edu)

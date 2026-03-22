# RepolyzeAI — Product Requirements Document (PRD)

**Version**: 1.0 | **Date**: 2026-03-22 | **Author**: Aayush + Claude
**Status**: Draft → Pending Approval

---

## 1. Executive Summary

**Problem**: Security auditing tools are fragmented, expensive, and don't cover AI agents. Most developers skip security reviews. AI agent safety (prompt injection, data leakage, tool misuse) is a blind spot across the industry — PromptFoo was acquired by OpenAI because this space is critical and underserved.

**Solution**: RepolyzeAI — a universal, AI-powered security audit platform where developers paste a GitHub repo URL and receive a comprehensive security report. It auto-detects AI agents (LangChain, CrewAI, ADK, OpenAI Agents SDK) and MCP servers, then runs both **code security auditing** and **AI agent red-teaming**. Built with Google ADK + A2A protocol, deployed on GCP.

**Tagline**: "Paste your repo. Know your risks. Ship with confidence."

**Three core capabilities**:
1. **Code Security Audit** — static analysis, dependency vulnerabilities, secret detection, license compliance (inspired by Semgrep 13.4k stars, Horusec multi-engine orchestration)
2. **AI Agent Safety Audit** — prompt injection, tool misuse, data leakage, auth bypass, guardrail validation. Both static analysis + live red-teaming (inspired by PromptFoo 17.6k stars, Garak 7.3k stars, PyRIT 1.5k stars)
3. **MCP Server Audit** — tool permission analysis, input validation, auth checks on MCP tool definitions

**Target**: Individual developers. **Pricing**: Freemium (free tier 5-10 scans/month, Pro tier unlimited). **MVP timeline**: 2 weeks.

---

## Features Stolen from Top Projects

### From PromptFoo (17.6k stars — acquired by OpenAI)
- **YAML-based red-team config** — declarative test definitions, not hardcoded
- **50+ vulnerability types** covering OWASP LLM Top 10 + NIST AI RMF
- **LLM-as-Judge scoring** — use Gemini to grade whether responses are safe
- **Multi-model comparison** — test same prompts across different agent configs
- **CI/CD integration** — run as GitHub Action, output SARIF reports

### From Garak (7.3k stars — NVIDIA)
- **100+ attack probe modules** organized by risk category
- **Plugin architecture** — base classes for extending probes, detectors, evaluators
- **Multi-layer detection** — string matching + ML classifiers + LLM-as-judge
- **Structured evaluation** — multiple generations per prompt (default: 10) with aggregation
- **Attack categories**: jailbreaks (DAN, grandma), injection, encoding-based, XSS vectors, glitch tokens, adversarial suffixes (GCG)

### From PyRIT (1.5k stars — Microsoft AI Red Team)
- **Multi-turn attack orchestration** — adaptive attacks that escalate based on responses
- **Converter system** — transform prompts (translate, rephrase, add overlays, encoding tricks)
- **Memory system** — track all conversations and scores for reproducibility
- **Named attack strategies**: Crescendo (gradual escalation), TAP (tree of attacks with pruning), Skeleton Key
- **Scorer framework** — binary, Likert scale, classification-based, LLM-powered scoring

### From Anthropic's Safety Tools
- **Petri pattern** — auditor agent + judge component + transcript viewer for multi-turn testing
- **Bloom pattern** — 4-stage behavioral evaluation (Understanding → Ideation → Rollout → Judgment)
- **36 scoring dimensions** for agent behavior evaluation
- **Dictionary learning** — monitor neural features for deception, sycophancy, power-seeking
- **SHADE-Arena** — long-horizon simulations where agents pursue hidden objectives

### From DeepTeam (1.3k stars — Confident AI)
- **40+ vulnerability types** with OWASP + NIST framework alignment
- **Multi-turn exploitation** testing (not just single-shot prompts)
- **Bias and PII leakage** specific test suites
- **Data poisoning detection** patterns

### From Guardrails AI (6k+ stars)
- **Validator architecture** — composable safety checkers that can be combined
- **Input/output guard pattern** — detect missing guardrails in agent code
- **Fine-grained control flows** — what happens when validation fails

### OWASP LLM Top 10 (2025) — Full Coverage
1. Prompt Injection (manipulating inputs to override instructions)
2. Insecure Output Handling (XSS, CSRF, RCE from unvalidated outputs)
3. Training Data Poisoning (backdoors, biases in training data)
4. Vector & Embedding Weaknesses (RAG system vulnerabilities)
5. Supply Chain Vulnerabilities (compromised models, plugins, dependencies)
6. Insecure Plugins/Tools (inadequate input validation, missing access controls)
7. Model Denial of Service (resource exhaustion attacks)
8. Sensitive Information Disclosure (system prompt leakage, PII exposure)
9. Overreliance & Misinformation (hallucination acceptance)
10. Insecure Model Access (unauthorized access to models)

---

## 2. Tech Stack

| Layer | Choice | Why |
|-------|--------|-----|
| Frontend | Next.js 15 (App Router) + Tailwind + shadcn/ui | SSR, streaming, Vercel deploy |
| Backend | Python FastAPI + Celery + Redis | ADK/A2A native, scanning tools are Python |
| Agent Framework | Google ADK + A2A protocol | Independent agents, Vertex AI deployment |
| Database | Supabase PostgreSQL | Auth + DB + Storage + Realtime |
| Auth | Supabase Auth + GitHub OAuth | Native GitHub integration for private repos |
| PDF Generation | WeasyPrint (server-side) | Professional quality, Jinja2 templates |
| Code Scanning | Semgrep, Bandit, TruffleHog, osv-scanner | Open source, multi-language |
| Agent Red-teaming | Gemini 2.5 + custom adversarial prompts | Prompt injection, jailbreak, data exfil |
| AI Analysis | Gemini 2.5 Flash/Pro via ADK | Contextual vulnerability review |
| Deployment | Vercel (frontend) + Cloud Run (backend) + Vertex AI (agents) | Best tool per layer |

---

## 3. System Architecture

```
User → Paste GitHub URL → Next.js Frontend (Vercel)
                              │
                              ▼
                    FastAPI Backend (Cloud Run)
                              │
                    ┌─────────▼──────────┐
                    │  Scan Orchestrator  │ (ADK root_agent)
                    │  1. Clone repo      │
                    │  2. Detect languages │
                    │  3. Detect AI agents │  ← NEW: auto-detect agent frameworks
                    │  4. Detect MCP svrs │  ← NEW: find MCP configs
                    │  5. Dispatch agents  │
                    └─────────┬──────────┘
                              │ A2A Protocol (parallel dispatch)
         ┌────────────────────┼────────────────────┐
         │                    │                    │
   ══CODE AUDIT══      ══AGENT AUDIT══     ══INFRA AUDIT══
         │                    │                    │
    ┌────▼────┐    ┌──────────▼─────────┐   ┌─────▼──────┐
    │ Static  │    │ Agent Safety       │   │ MCP Server │
    │ Analysis│    │ Auditor            │   │ Auditor    │
    │ Semgrep │    │                    │   │            │
    │ Bandit  │    │ Static checks:     │   │ • Tool     │
    └─────────┘    │ • Missing guards   │   │   permission│
    ┌─────────┐    │ • Unsafe tools     │   │   analysis │
    │ Depend- │    │ • Prompt injection │   │ • Input    │
    │ ency    │    │   vectors          │   │   validation│
    │ Audit   │    │                    │   │ • Auth     │
    │ osv-scan│    │ Live red-team:     │   │   checks   │
    └─────────┘    │ • Jailbreak tests  │   └────────────┘
    ┌─────────┐    │ • Data exfil tests │
    │ Secret  │    │ • Tool abuse tests │
    │ Detect  │    │ • Auth bypass tests│
    │ Truffleh│    └───────────────────-┘
    └─────────┘
    ┌─────────┐
    │ License │
    │ Check   │
    └─────────┘
         │                    │                    │
         └────────────────────┼────────────────────┘
                              ▼
                    Report Aggregator
                    → Deduplicate + score severity
                    → OWASP Top 10 mapping
                    → Agent safety score (A-F grade)
                    → Generate PDF (WeasyPrint)
                    → Store in Supabase
                              │
                              ▼
                    Interactive report + PDF download
```

### AI Agent Detection (Auto-Detect)

When a repo is scanned, we auto-detect:
- **LangChain**: imports from `langchain`, `langchain_core`, `langgraph`
- **CrewAI**: imports from `crewai`, `crewai_tools`
- **Google ADK**: imports from `google.adk`, `google.genai`
- **OpenAI Agents SDK**: imports from `openai.agents`, `openai.swarm`
- **MCP Servers**: `mcp.json`, `claude_desktop_config.json`, `@modelcontextprotocol/sdk` imports

If agents detected → trigger Agent Safety Audit automatically alongside code audit.

### AI Agent Red-Teaming (Live) — Inspired by PromptFoo + Garak + PyRIT

**YAML-based test config** (stolen from PromptFoo):
```yaml
# agents/agent_safety/prompts/redteam-config.yaml
redteam:
  plugins:
    - owasp:llm           # OWASP LLM Top 10 preset
    - prompt-injection     # 15+ injection variants
    - jailbreak            # DAN, grandma, encoding tricks, GCG suffixes
    - data-exfiltration    # System prompt extraction, PII probing
    - tool-abuse           # Unauthorized tool usage, privilege escalation
    - auth-bypass          # Role impersonation, admin access
    - multi-turn           # Crescendo attacks (from PyRIT)
  scoring:
    method: llm-as-judge   # Gemini grades responses
    threshold: 0.7         # Fail if safety score < 0.7
  iterations: 5            # Multiple attempts per probe (from Garak)
```

**Attack orchestration** (stolen from PyRIT):
1. **Single-turn attacks**: Direct adversarial prompts (100+ from Garak's probe library)
2. **Multi-turn attacks**: Crescendo (gradual escalation), TAP (tree of attacks with pruning)
3. **Converter pipeline**: Base prompt → translate → rephrase → encode (Base64, ROT13, Unicode) → send
4. **Memory tracking**: All prompts + responses stored for reproducibility
5. **Adaptive strategy**: If agent blocks direct injection, try encoding tricks, then multi-turn

**Scoring system** (stolen from PromptFoo + PyRIT):
- **LLM-as-Judge**: Gemini evaluates if response is safe (pass/fail + reasoning)
- **Multi-dimensional scoring**: 10 dimensions (safety, helpfulness, honesty, harm-refusal, etc.)
- **Overall safety grade**: A (95%+ pass) → F (<50% pass)
- **OWASP LLM compliance score**: Per-category pass rates mapped to Top 10

**What we test** (stolen from Garak's 100+ probes):
- Prompt injection (15 variants: direct, indirect, nested, encoded)
- Jailbreaks (20 variants: DAN, grandma appeal, roleplay, encoding)
- Data exfiltration (10 variants: system prompt, training data, PII)
- Tool/plugin abuse (10 variants: file access, shell exec, network)
- Authorization bypass (10 variants: role switching, admin impersonation)
- Toxic content generation (10 variants: violence, hate, illegal)
- Hallucination probing (5 variants: fabricated citations, fake facts)
- Multi-turn exploitation (10 variants: Crescendo, TAP, Skeleton Key)

### A2A Agent Communication

Each agent is an independent A2A-compliant service:
- **Agent Card** (`/.well-known/agent.json`): Declares capabilities, skills, endpoint
- **Task lifecycle**: `tasks/send` → `tasks/get` for async scanning
- **Streaming**: `tasks/sendSubscribe` for real-time progress
- Agents deployed independently on Cloud Run or Vertex AI Agent Engine

---

## 4. Database Schema

```sql
profiles        -- extends Supabase Auth (github_username, plan, scans_remaining)
scans           -- per submission (repo_url, status, progress, language/agent detection results)
findings        -- vulnerabilities (severity, CWE, category, agent_name, tool_name, remediation)
agent_findings  -- AI agent safety findings (test_type, prompt_used, response, pass/fail, risk_level)
reports         -- generated PDFs (storage_path, html_cache, summary_json)
api_keys        -- for CI/CD programmatic access
```

---

## 5. API Endpoints

```
POST   /api/scans                            -- Start scan {repo_url, branch, api_keys?}
GET    /api/scans/:id                        -- Status + summary
GET    /api/scans/:id/progress               -- SSE stream
GET    /api/scans/:id/findings               -- Code findings (filterable)
GET    /api/scans/:id/agent-findings         -- Agent safety findings
POST   /api/scans/:id/reports                -- Generate PDF
GET    /api/scans/:id/reports/:rid/download  -- Download PDF
POST   /api/auth/github                      -- GitHub OAuth
GET    /api/health                           -- Health check
```

---

## 6. Implementation Timeline (2-Week MVP)

### Week 1: Core Pipeline (Days 1-7)

**Day 1-2: Project Bootstrap**
- [ ] Create GCP project (`gcloud projects create repolyze-ai`)
- [ ] Enable APIs (aiplatform, run, cloudbuild, secretmanager)
- [ ] Init monorepo: `frontend/` + `backend/` + `agents/`
- [ ] Next.js 15 scaffold with Tailwind + shadcn/ui
- [ ] FastAPI scaffold with project structure
- [ ] Supabase project + initial migration (scans, findings tables)
- [ ] Docker Compose (Redis + PostgreSQL for local dev)
- [ ] GitHub repo + CI (lint/typecheck)

**Day 3-4: Scan Pipeline MVP**
- [ ] Landing page: GitHub URL input + "Scan" button
- [ ] `POST /api/scans`: validate URL, clone repo (`git clone --depth 1`)
- [ ] Language detection (file extension counting)
- [ ] **Agent detection**: grep for LangChain/CrewAI/ADK/OpenAI imports
- [ ] **MCP detection**: find mcp.json, MCP SDK imports
- [ ] Celery task for background scanning
- [ ] Semgrep tool wrapper (run CLI → parse JSON → normalize findings)
- [ ] Store findings in Supabase

**Day 5-6: Agent Safety Audit (Static)**
- [ ] Agent Safety Auditor: static analysis patterns
  - Missing input validation/guardrails
  - Unsafe tool configurations (file system access, shell exec)
  - System prompt exposure risks
  - Missing rate limiting / auth checks
  - Hardcoded API keys in agent code
- [ ] MCP Server Auditor: analyze tool definitions
  - Overly permissive tool scopes
  - Missing input validation on tool parameters
  - No auth/permission checks
- [ ] Findings normalized into same schema with `category: 'agent_safety'`

**Day 7: Results UI**
- [ ] Scan progress page (polling → SSE later)
- [ ] Findings table with severity badges + filters
- [ ] Agent detection indicator ("AI Agents Detected: LangChain, MCP Server")
- [ ] Separate sections: Code Findings vs Agent Safety Findings
- [ ] Summary cards (Critical/High/Medium/Low counts)

### Week 2: Reports + Red-Teaming + Polish (Days 8-14)

**Day 8-9: Live Agent Red-Teaming (PromptFoo + Garak + PyRIT inspired)**
- [ ] Adversarial probe library (90+ prompts in YAML, stolen from Garak's probe structure)
  - prompt_injection.yaml (15 variants: direct, indirect, nested, encoded)
  - jailbreak.yaml (20 variants: DAN, grandma, roleplay, encoding tricks)
  - data_exfiltration.yaml (10 variants: system prompt, PII, training data)
  - tool_abuse.yaml (10 variants: file system, shell, network, email)
  - auth_bypass.yaml (10 variants: admin impersonation, role switching)
  - toxic_content.yaml (10 variants)
  - hallucination.yaml (5 variants)
  - multi_turn.yaml (10 multi-turn attack chains)
- [ ] YAML-based red-team config (PromptFoo-style declarative test definitions)
- [ ] Converter pipeline (PyRIT-inspired): base → translate → rephrase → encode → send
- [ ] Multi-turn attack orchestrator with Crescendo + TAP strategies (from PyRIT)
- [ ] Sandboxed agent execution (Docker container, no network, 60s timeout)
- [ ] Auto-generate test harness per framework (LangChain/CrewAI/ADK/OpenAI)
- [ ] LLM-as-Judge scoring: Gemini evaluates each response (pass/fail + reasoning)
- [ ] Multi-dimensional scoring (10 dimensions) + overall A-F safety grade
- [ ] OWASP LLM Top 10 compliance mapping
- [ ] Memory system: store all prompts + responses for reproducibility

**Day 10-11: PDF Report Generation**
- [ ] WeasyPrint + Jinja2 templates
  - Cover page (repo name, date, overall grade)
  - Executive summary (risk score, key findings, agent safety grade)
  - Code security findings (grouped by OWASP category)
  - Agent safety findings (grouped by test type)
  - MCP server audit results
  - Remediation recommendations
- [ ] Store PDF in Supabase Storage
- [ ] Download endpoint

**Day 12-13: Multi-Agent + A2A Foundation**
- [ ] ADK agent definitions for each scanner
- [ ] A2A agent cards (`/.well-known/agent.json`)
- [ ] Orchestrator dispatches to agents via A2A `tasks/send`
- [ ] Parallel execution (all agents run simultaneously)
- [ ] TruffleHog secret detection agent
- [ ] osv-scanner dependency audit agent

**Day 14: Auth + Polish + Deploy**
- [ ] Supabase Auth with GitHub OAuth
- [ ] User dashboard (scan history)
- [ ] Free tier quota enforcement (10 scans/month)
- [ ] Deploy frontend to Vercel
- [ ] Deploy backend to Cloud Run
- [ ] End-to-end smoke test

---

## 7. Post-MVP Roadmap (Weeks 3-8)

### Week 3-4: Enhanced Scanning
- [ ] Full Vertex AI Agent Engine deployment for all agents
- [ ] CodeQL integration (semantic analysis, 88% accuracy)
- [ ] Guardrails AI validator detection (check if agents use guardrails)
- [ ] NeMo Guardrails config analysis (detect NVIDIA guardrail patterns)
- [ ] Historical scan comparison (diff between scans)
- [ ] SARIF output format for GitHub Security tab integration

### Week 5-6: Platform Features
- [ ] GitHub Action (`repolyze-ai/scan-action`)
- [ ] API key management for CI/CD
- [ ] Webhook notifications (email, Slack)
- [ ] Custom Semgrep rules upload
- [ ] Bloom-style behavioral evaluation (Anthropic pattern — generate varied scenarios per run)
- [ ] Plugin architecture (Garak-style) — community can add custom probes + detectors

### Week 7-8: Monetization + Scale
- [ ] Pro tier billing (Stripe integration)
- [ ] Team/organization accounts
- [ ] More framework support (AutoGen, Semantic Kernel, Haystack)
- [ ] AIVSS scoring (OWASP AI Vulnerability Scoring System)
- [ ] Compliance report templates (SOC2, ISO 27001)
- [ ] Self-hosted option for enterprise

---

## 8. Project Structure

```
repolyze-ai/
├── frontend/                        # Next.js 15
│   └── src/
│       ├── app/
│       │   ├── page.tsx             # Landing (URL input)
│       │   ├── scan/[id]/page.tsx   # Progress + results
│       │   ├── report/[id]/page.tsx # Interactive report
│       │   └── dashboard/page.tsx   # Scan history
│       ├── components/
│       │   ├── ui/                  # shadcn/ui
│       │   ├── scan/                # URL input, progress, history
│       │   └── report/              # Findings table, severity, code snippet
│       └── lib/
│           ├── supabase/            # Client + server clients
│           └── api.ts               # Backend API client
├── backend/                         # Python FastAPI
│   ├── app/
│   │   ├── api/                     # Route handlers (scans, findings, reports, auth)
│   │   ├── models/                  # Pydantic schemas
│   │   ├── db/                      # Repository pattern (Supabase)
│   │   └── services/                # Business logic (scan, report, github)
│   ├── workers/                     # Celery tasks (scan_tasks, report_tasks)
│   └── report/
│       ├── generator.py             # WeasyPrint PDF
│       └── templates/               # Jinja2 HTML templates
├── agents/                          # ADK + A2A agents
│   ├── orchestrator/                # Root agent (dispatch + aggregate)
│   ├── static_analysis/             # Semgrep, Bandit
│   ├── dependency_audit/            # osv-scanner, pip-audit, npm audit
│   ├── secret_detection/            # TruffleHog
│   ├── agent_safety/                # AI agent auditor (static + red-team)
│   │   ├── detector.py              # Auto-detect agent frameworks
│   │   ├── static_analyzer.py       # Pattern-based agent code analysis
│   │   ├── red_team/                # Live adversarial testing (PyRIT-inspired)
│   │   │   ├── orchestrator.py      # Multi-turn attack orchestration
│   │   │   ├── converters.py        # Prompt converters (encode, translate, rephrase)
│   │   │   ├── scorers.py           # LLM-as-judge + multi-dimensional scoring
│   │   │   ├── harness_generator.py # Auto-generate test harness per framework
│   │   │   └── strategies/          # Named attack strategies (from PyRIT)
│   │   │       ├── crescendo.py     # Gradual escalation
│   │   │       ├── tap.py           # Tree of attacks with pruning
│   │   │       └── skeleton_key.py  # Specific jailbreak methodology
│   │   └── probes/                  # Adversarial prompt library (Garak-inspired)
│   │       ├── prompt_injection.yaml     # 15 variants
│   │       ├── jailbreak.yaml            # 20 variants (DAN, grandma, roleplay)
│   │       ├── data_exfiltration.yaml    # 10 variants
│   │       ├── tool_abuse.yaml           # 10 variants
│   │       ├── auth_bypass.yaml          # 10 variants
│   │       ├── toxic_content.yaml        # 10 variants
│   │       ├── hallucination.yaml        # 5 variants
│   │       ├── multi_turn.yaml           # 10 multi-turn attack chains
│   │       └── redteam-config.yaml       # PromptFoo-style YAML config
│   ├── mcp_auditor/                 # MCP server security audit
│   ├── ai_review/                   # Gemini contextual review
│   └── license_compliance/          # License checker
├── supabase/
│   └── migrations/                  # SQL schema
├── docker-compose.yml               # Local dev
├── .env.example
└── CLAUDE.md
```

---

## 9. GCP Project Setup

```bash
gcloud projects create repolyze-ai --name="RepolyzeAI"
gcloud config set project repolyze-ai
gcloud services enable \
  aiplatform.googleapis.com \
  run.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  redis.googleapis.com \
  secretmanager.googleapis.com
```

---

## 10. Risks & Mitigations

| Risk | Mitigation |
|------|-----------|
| Malicious repo code execution | `--depth 1 --no-checkout`, skip git hooks, sandboxed containers, no code execution |
| Live red-teaming runs untrusted agents | Docker sandbox with no network, CPU/memory limits, 60s timeout |
| Large repos overwhelm scanners | 500MB size limit, shallow clone, 15-min total timeout |
| AI analysis cost | Only analyze flagged files, token budget per scan, Gemini Flash for triage |
| Abuse / rate limiting | 3/hour unauthenticated, 10/month free tier, scan deduplication |
| 2-week timeline risk | MVP focuses on Semgrep + agent static analysis; live red-teaming can be basic |

---

## 11. Verification & Testing

1. **Code scan test**: Paste `https://github.com/OWASP/WebGoat` → get code vulnerability findings
2. **Agent detection test**: Paste a LangChain project repo → auto-detect agents, show agent safety findings
3. **MCP audit test**: Paste a repo with MCP server config → audit tool definitions
4. **Red-team test**: Provide API keys → run adversarial prompts against detected agent → see pass/fail results
5. **PDF test**: Download report → verify cover page, executive summary, code findings, agent safety grade, remediation
6. **A2A test**: Each agent responds to `/.well-known/agent.json` and processes tasks independently
7. **Auth test**: Sign in with GitHub → scan private repo → view in dashboard

---

## 12. Pre-Implementation Setup (Immediately After Approval)

Before writing any code, I will:

1. **Create PRD document** — Save this plan as `docs/PRD.md` in the project
2. **Generate PDF** — Create a professional PDF version of this PRD on your Desktop
3. **Initialize memory system** — Create persistent memory at `~/.claude/projects/.../memory/`:
   - `decisions.md` — Architectural and technical decisions made
   - `people.md` — Collaborators and stakeholders
   - `preferences.md` — User's coding preferences and workflow
   - `user.md` — User profile and context
4. **Create CLAUDE.md** — Project-level instructions that auto-load each session, including:
   - Read memory files at session start
   - Update memory files at session end
   - Project conventions and patterns
   - Key file paths and architecture overview

---

## 13. Inspiration & References (by star count)

### AI/LLM Security (Features to steal)
| Project | Stars | What to steal |
|---------|-------|--------------|
| **PromptFoo** (promptfoo/promptfoo) | 17.6k | YAML config, 50+ vuln types, LLM-as-judge, CI/CD integration |
| **Garak** (NVIDIA/garak) | 7.3k | 100+ probe modules, plugin architecture, multi-layer detection |
| **Guardrails AI** (guardrails-ai/guardrails) | 6k+ | Validator architecture, composable safety checkers |
| **PyRIT** (Azure/PyRIT) | 1.5k | Multi-turn orchestration, converters, memory, named strategies |
| **DeepTeam** (confident-ai/deepteam) | 1.3k | 40+ vuln types, OWASP+NIST alignment, bias detection |

### Code Security (Features to steal)
| Project | Stars | What to steal |
|---------|-------|--------------|
| **Semgrep** (semgrep/semgrep) | 13.4k | Pattern-as-code, 30+ languages, YAML rules |
| **SonarQube** (SonarSource/sonarqube) | 10.3k | Quality + security + compliance dashboard |
| **Horusec** (ZupIT/horusec) | 1.3k | Multi-engine orchestration, git history scanning |
| **Bearer** (Bearer/bearer) | 2.5k | Data flow analysis, privacy-focused SAST |

### Anthropic Safety Research (Patterns to implement)
- **Petri**: Multi-turn auditor agent + judge + transcript viewer
- **Bloom**: 4-stage behavioral evaluation with varied scenario generation
- **SHADE-Arena**: Long-horizon agent safety testing
- **Claude Code Security**: AI reasoning for contextual vulnerability analysis

### Other References
- **Chain-Fox** (github.com/Chain-Fox/Chain-Fox): User's previous project
- **evilsocket/code-audit**: AI security audit agent
- **anthropics/claude-code-security-review**: Claude-powered GitHub Action
- **Google ADK**: google.github.io/adk-docs
- **A2A protocol**: google.github.io/A2A
- **OWASP LLM Top 10**: genai.owasp.org/llm-top-10
- **OWASP AIVSS**: aivss.owasp.org (AI Vulnerability Scoring System)

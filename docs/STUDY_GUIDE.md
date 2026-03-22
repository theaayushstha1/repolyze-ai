# RepolyzeAI — Study Guide

Everything used in this project, explained simply.

---

## 1. The Big Picture

RepolyzeAI is a web app where someone pastes a GitHub URL and gets a security audit report.

```
User → Pastes URL → Frontend sends to Backend → Backend clones repo →
→ Runs scanners (Semgrep, agent safety, MCP audit) →
→ Returns findings → Shows in UI → Downloads as PDF
```

---

## 2. Frontend Stack

### Next.js 15
**What:** A React framework that adds server-side rendering, routing, and API routes on top of React.
**Why we use it:** Instead of building React + a router + a server separately, Next.js gives us everything. The "App Router" means our file structure (`app/page.tsx`, `app/scan/[id]/page.tsx`) automatically becomes our URL routes.
**How it works:** Files in `src/app/` become pages. `page.tsx` = the page content. `layout.tsx` = the wrapper around pages. `[id]` in folder names = dynamic URL parameters.

### Tailwind CSS
**What:** A CSS framework where you style things using class names instead of writing CSS files.
**Why:** `className="text-lg font-bold text-red-500"` is faster than creating CSS classes. No switching between files.
**How:** Each class does one thing: `text-lg` = larger text, `font-bold` = bold, `bg-primary` = primary color background.

### shadcn/ui
**What:** Pre-built React components (buttons, cards, tables, badges) that look professional.
**Why:** Instead of building a Button component from scratch, we install it and it's ready. Customizable because the code lives in our project (not hidden in node_modules).
**How:** `npx shadcn add button` → creates `src/components/ui/button.tsx`. We import and use: `<Button variant="outline">Click me</Button>`.

### TypeScript
**What:** JavaScript with types. Instead of `function add(a, b)`, you write `function add(a: number, b: number): number`.
**Why:** Catches bugs before they happen. If you try to pass a string where a number is expected, it tells you immediately.

---

## 3. Backend Stack

### FastAPI (Python)
**What:** A modern Python web framework for building APIs. Similar to Flask but faster and with automatic validation.
**Why:**
- Python because all our scanning tools (Semgrep, security analyzers) are Python
- FastAPI because it auto-generates API docs at `/docs` (Swagger UI)
- Built-in request validation using Pydantic models
**How:** You define endpoints with decorators:
```python
@router.post("/api/scans")
async def create_scan(body: ScanCreate) -> ScanResponse:
    # FastAPI automatically validates the request body
    # and generates API documentation
```

### Pydantic
**What:** Data validation library. You define what your data should look like, and it validates automatically.
**Why:** If someone sends `{"repo_url": 123}` instead of a string, Pydantic rejects it immediately.
**How:**
```python
class ScanCreate(BaseModel):
    repo_url: str      # Must be a string
    branch: str = "main"  # Optional, defaults to "main"
```

### Celery + Redis
**What:** Celery = background task queue. Redis = the message broker that coordinates tasks.
**Why:** Scanning a repo takes 30-120 seconds. You can't make the user wait that long for an HTTP response. Celery runs the scan in the background while the user watches progress.
**How:**
1. User creates scan → API responds immediately with scan ID
2. Celery task starts in background → clones repo → runs scanners
3. Frontend polls for progress every 3 seconds

### Supabase
**What:** An open-source Firebase alternative. Gives you PostgreSQL database + authentication + file storage + real-time subscriptions in one service.
**Why:** Instead of setting up PostgreSQL + building auth + building file uploads separately, Supabase gives us everything. Plus GitHub OAuth built-in.
**How:** We store scans, findings, reports, and user profiles in Supabase's PostgreSQL database.

---

## 4. Scanning Tools

### Semgrep
**What:** A static analysis tool that finds security vulnerabilities by pattern matching. It looks at your code without running it.
**Why:** Supports 30+ languages, has thousands of pre-built security rules, and is fast.
**How:** `semgrep scan --config=auto --json /path/to/repo` → outputs a JSON list of findings with file paths, line numbers, severity, and descriptions.
**What it finds:** SQL injection, XSS, hardcoded secrets, insecure crypto, path traversal, etc.

### Agent Safety Static Analyzer (custom)
**What:** Our own analyzer that scans Python files for AI agent security issues.
**Why:** No existing tool does this — this is our unique value.
**What it checks:**
- `eval()` / `exec()` calls → code injection risk
- `subprocess.run()` / `os.system()` → shell command injection
- Hardcoded API keys (regex patterns like `sk-...`, `AKIA...`)
- Missing guardrails on LangChain/CrewAI/ADK agent definitions
- Missing rate limiting on API-facing code

### MCP Auditor (custom)
**What:** Analyzes Model Context Protocol server implementations for security issues.
**Why:** MCP is new, nobody else audits it — first mover advantage.
**What it checks:**
- Shell execution in MCP tools (dangerous if user-controlled)
- Unrestricted file access (read/write without path validation)
- Missing input validation on tool parameters
- Insecure transport (HTTP instead of HTTPS)

---

## 5. Agent Architecture

### Google ADK (Agent Development Kit)
**What:** Google's framework for building AI agents. Each agent is an `LlmAgent` with a model, instructions, and tools.
**Why:** Native Vertex AI deployment, supports Gemini models, has built-in A2A (Agent-to-Agent) protocol support.
**How:**
```python
agent = LlmAgent(
    name="StaticAnalysis",
    model="gemini-2.5-flash",
    tools=[semgrep_scan, bandit_scan],
    instruction="You are a security scanner..."
)
```

### A2A Protocol (Agent-to-Agent)
**What:** Google's protocol for agents to communicate with each other, regardless of framework.
**Why:** Each scanner agent can be deployed independently and talk to others. The orchestrator discovers agents via their "agent cards."
**How:** Each agent exposes `/.well-known/agent.json` describing its capabilities. The orchestrator sends tasks via `POST /tasks/send`.

### Agent Frameworks We Detect
- **LangChain** (17k+ stars) — Most popular agent framework. Chains LLM calls together.
- **CrewAI** — Multi-agent framework where agents have roles (researcher, writer, etc.)
- **Google ADK** — Google's agent framework with Vertex AI integration.
- **OpenAI Agents SDK** — OpenAI's agent framework (formerly Swarm).

---

## 6. Red-Teaming System

### What is Red-Teaming?
Testing AI agents by attacking them with adversarial prompts to find safety failures. Like penetration testing but for AI.

### Our Approach (inspired by 3 projects)

**From PromptFoo (17.6k stars, acquired by OpenAI):**
- YAML-based test config — define tests declaratively, not in code
- LLM-as-Judge — use Gemini to evaluate if a response is safe

**From Garak (7.3k stars, NVIDIA):**
- 90+ adversarial probes organized by category
- Plugin architecture — easy to add new attack types

**From PyRIT (1.5k stars, Microsoft):**
- Multi-turn attacks — gradually escalate, not just one-shot
- Converters — transform prompts (Base64 encode, ROT13, leetspeak) to bypass filters
- Named strategies: Crescendo (gradual), TAP (tree of attacks), Skeleton Key

### OWASP LLM Top 10 (2025)
The "OWASP Top 10" but for AI/LLM applications:
1. **Prompt Injection** — tricking the AI into ignoring its instructions
2. **Insecure Output Handling** — AI output causes XSS/SQL injection downstream
3. **Training Data Poisoning** — corrupted training data creates backdoors
4. **Vector & Embedding Weaknesses** — RAG system vulnerabilities
5. **Supply Chain Vulnerabilities** — compromised models/plugins
6. **Insecure Plugins/Tools** — tools without proper validation
7. **Model Denial of Service** — overloading the AI
8. **Sensitive Information Disclosure** — AI leaks system prompts or PII
9. **Overreliance & Misinformation** — trusting AI output blindly
10. **Insecure Model Access** — unauthorized access to models

---

## 7. Infrastructure

### Docker Compose
**What:** Defines multiple services (database, Redis, backend) that run together.
**Why:** One command (`docker compose up`) starts everything needed for local development.
**Services we define:** PostgreSQL (database), Redis (task queue), Backend (FastAPI), Celery Worker.

### Cloud Run (GCP)
**What:** Google's serverless container platform. Upload a Docker container, it runs and scales automatically.
**Why:** Pay-per-use, auto-scales to zero when idle, handles HTTPS/load balancing.

### Vertex AI Agent Engine
**What:** Google's managed platform for deploying AI agents.
**Why:** Our ADK agents can be deployed here for production scaling, built-in monitoring, and threat detection.

### GitHub Actions CI
**What:** Automated testing that runs on every git push/PR.
**Why:** Catches broken code before it gets merged. Runs lint + typecheck + tests automatically.

---

## 8. PDF Report Generation

### ReportLab
**What:** Python library for creating PDFs programmatically.
**Why:** Server-side PDF generation is more reliable than browser-based. We control the layout precisely.
**How:** We build a "story" (list of elements: paragraphs, tables, page breaks) and ReportLab renders it to PDF.

---

## 9. Key Design Patterns

### Repository Pattern
**What:** Database access goes through a dedicated "repository" layer, not directly in API endpoints.
**Why:** If we switch from Supabase to Cloud SQL, we only change the repository files — not every endpoint.
```
API endpoint → calls scan_repo.create_scan() → repo talks to database
```

### Immutability
**What:** Never modify existing objects. Create new ones instead.
**Why:** Prevents bugs from unexpected side effects. When data flows through the system, you know it hasn't been changed.
```python
class Finding(BaseModel, frozen=True):  # Can't be modified after creation
```

### In-Memory Demo Mode
**What:** The backend can run without any database using an in-memory store.
**Why:** Lets you test the full app locally without setting up Supabase/Redis/PostgreSQL.

---

## 10. Glossary

| Term | Meaning |
|------|---------|
| **SAST** | Static Application Security Testing — analyzing code without running it |
| **CVE** | Common Vulnerabilities and Exposures — unique IDs for known vulnerabilities |
| **CWE** | Common Weakness Enumeration — categories of software weaknesses |
| **OWASP** | Open Web Application Security Project — nonprofit for web security standards |
| **SSE** | Server-Sent Events — server pushes updates to the browser in real-time |
| **CORS** | Cross-Origin Resource Sharing — allows frontend on port 3000 to call backend on port 8000 |
| **JWT** | JSON Web Token — compact token for authentication |
| **SARIF** | Static Analysis Results Interchange Format — standard format for scanner output |
| **MCP** | Model Context Protocol — Anthropic's protocol for LLM tool access |
| **A2A** | Agent-to-Agent — Google's protocol for agents to communicate |
| **ADK** | Agent Development Kit — Google's framework for building AI agents |
| **RAG** | Retrieval-Augmented Generation — feeding external data to LLMs |
| **RLS** | Row-Level Security — database feature that restricts which rows users can see |
| **BFF** | Backend-for-Frontend — a lightweight API layer between frontend and main backend |

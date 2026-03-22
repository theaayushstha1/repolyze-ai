import { ScanForm } from "@/components/scan/scan-form";
import { FeatureCards } from "@/components/scan/feature-cards";

export default function HomePage() {
  return (
    <main className="flex-1 flex flex-col">
      {/* Header */}
      <header className="border-b border-border/40 bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container mx-auto flex h-14 items-center px-4">
          <div className="flex items-center gap-2 font-bold text-lg">
            <span className="text-primary">Repolyze</span>
            <span className="text-muted-foreground">AI</span>
          </div>
          <nav className="ml-auto flex items-center gap-4 text-sm">
            <a href="/dashboard" className="text-muted-foreground hover:text-foreground transition-colors">
              Dashboard
            </a>
            <a href="/auth/login" className="text-muted-foreground hover:text-foreground transition-colors">
              Sign in
            </a>
          </nav>
        </div>
      </header>

      {/* Hero */}
      <section className="flex-1 flex flex-col items-center justify-center px-4 py-16">
        <div className="max-w-3xl mx-auto text-center space-y-6">
          <h1 className="text-4xl sm:text-5xl lg:text-6xl font-bold tracking-tight">
            Paste your repo.
            <br />
            <span className="text-primary">Know your risks.</span>
          </h1>
          <p className="text-lg text-muted-foreground max-w-xl mx-auto">
            AI-powered security auditing for your codebase. Auto-detects AI agents,
            scans for vulnerabilities, and generates professional PDF reports.
          </p>

          <ScanForm />

          <div className="flex items-center justify-center gap-6 text-xs text-muted-foreground pt-4">
            <span>30+ languages</span>
            <span className="w-1 h-1 rounded-full bg-muted-foreground" />
            <span>AI agent red-teaming</span>
            <span className="w-1 h-1 rounded-full bg-muted-foreground" />
            <span>MCP server audit</span>
            <span className="w-1 h-1 rounded-full bg-muted-foreground" />
            <span>PDF reports</span>
          </div>
        </div>
      </section>

      {/* Features */}
      <section className="border-t bg-muted/30 py-16 px-4">
        <div className="max-w-5xl mx-auto">
          <h2 className="text-2xl font-bold text-center mb-10">
            Three audit engines. One scan.
          </h2>
          <FeatureCards />
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t py-6 px-4">
        <div className="container mx-auto flex items-center justify-between text-xs text-muted-foreground">
          <span>RepolyzeAI &copy; 2026</span>
          <div className="flex gap-4">
            <span>Powered by Gemini + ADK</span>
            <span>Built by Aayush</span>
          </div>
        </div>
      </footer>
    </main>
  );
}

import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";

const FEATURES = [
  {
    title: "Code Security",
    description: "Static analysis across 30+ languages",
    details: [
      "Semgrep pattern matching",
      "Dependency CVE scanning",
      "Secret & credential detection",
      "License compliance checks",
    ],
  },
  {
    title: "AI Agent Safety",
    description: "Red-team your AI agents automatically",
    details: [
      "Auto-detect LangChain, CrewAI, ADK, OpenAI",
      "90+ adversarial prompt probes",
      "Multi-turn attack orchestration",
      "A-F safety grade with OWASP mapping",
    ],
  },
  {
    title: "MCP Server Audit",
    description: "Audit Model Context Protocol servers",
    details: [
      "Tool permission analysis",
      "Input validation checks",
      "Authentication verification",
      "Scope & access control review",
    ],
  },
] as const;

export function FeatureCards() {
  return (
    <div className="grid md:grid-cols-3 gap-6">
      {FEATURES.map((feature) => (
        <Card key={feature.title} className="bg-background">
          <CardHeader>
            <CardTitle className="text-lg">{feature.title}</CardTitle>
            <CardDescription>{feature.description}</CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2 text-sm text-muted-foreground">
              {feature.details.map((detail) => (
                <li key={detail} className="flex items-start gap-2">
                  <span className="mt-1 w-1.5 h-1.5 rounded-full bg-primary shrink-0" />
                  {detail}
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

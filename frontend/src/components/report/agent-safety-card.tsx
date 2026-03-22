"use client";

import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import type { Finding } from "@/types/scan";

interface AgentSafetyCardProps {
  readonly grade: string | null;
  readonly findings: readonly Finding[];
  readonly agentsDetected: readonly string[] | null;
  readonly mcpDetected: boolean;
}

const GRADE_COLORS: Record<string, string> = {
  A: "text-green-600 bg-green-50 border-green-200",
  B: "text-lime-600 bg-lime-50 border-lime-200",
  C: "text-yellow-600 bg-yellow-50 border-yellow-200",
  D: "text-orange-600 bg-orange-50 border-orange-200",
  F: "text-red-600 bg-red-50 border-red-200",
};

const CATEGORY_LABELS: Record<string, string> = {
  missing_guardrail: "Missing Guardrails",
  "unsafe_tool:shell_exec": "Unsafe Shell Execution",
  "unsafe_tool:code_eval": "Code Eval Risk",
  hardcoded_secret: "Hardcoded Secrets",
  prompt_exposure: "Prompt Exposure",
  missing_rate_limit: "Missing Rate Limiting",
  mcp_security: "MCP Security",
  agent_safety: "Agent Safety",
};

export function AgentSafetyCard({ grade, findings, agentsDetected, mcpDetected }: AgentSafetyCardProps) {
  const agentFindings = findings.filter(
    (f) => f.agent_name === "agent_safety" || f.agent_name === "mcp_auditor" || f.agent_name === "redteam"
  );

  if (!grade && agentFindings.length === 0 && (!agentsDetected || agentsDetected.length === 0) && !mcpDetected) {
    return null;
  }

  // Group by category
  const byCategory: Record<string, Finding[]> = {};
  for (const f of agentFindings) {
    const cat = f.category || "other";
    if (!byCategory[cat]) byCategory[cat] = [];
    byCategory[cat].push(f);
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-lg">AI Agent & MCP Security</CardTitle>
          {grade && (
            <div className={`px-4 py-2 rounded-lg border text-2xl font-bold ${GRADE_COLORS[grade] || ""}`}>
              {grade}
            </div>
          )}
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Detection badges */}
        <div className="flex flex-wrap gap-2">
          {agentsDetected?.map((agent) => (
            <Badge key={agent} variant="secondary">{agent} detected</Badge>
          ))}
          {mcpDetected && <Badge variant="secondary">MCP Server detected</Badge>}
          {(!agentsDetected || agentsDetected.length === 0) && !mcpDetected && (
            <p className="text-sm text-muted-foreground">No AI agents or MCP servers detected</p>
          )}
        </div>

        {agentFindings.length > 0 && (
          <>
            <Separator />
            <div className="space-y-3">
              {Object.entries(byCategory).map(([category, catFindings]) => (
                <div key={category} className="space-y-1">
                  <p className="text-sm font-medium">
                    {CATEGORY_LABELS[category] || category.replace(/_/g, " ").replace(/:/g, " - ")}
                    <span className="text-muted-foreground ml-2">({catFindings.length})</span>
                  </p>
                  {catFindings.map((f) => (
                    <div key={f.id} className="flex items-start gap-2 pl-4 text-sm">
                      <Badge
                        variant={f.severity === "CRITICAL" ? "destructive" : f.severity === "HIGH" ? "destructive" : "secondary"}
                        className="text-xs shrink-0"
                      >
                        {f.severity}
                      </Badge>
                      <div className="min-w-0">
                        <p className="text-sm">{f.title}</p>
                        {f.file_path && (
                          <p className="text-xs text-muted-foreground font-mono truncate">
                            {f.file_path}{f.line_start ? `:${f.line_start}` : ""}
                          </p>
                        )}
                        {f.remediation && (
                          <p className="text-xs text-muted-foreground mt-0.5">
                            Fix: {f.remediation}
                          </p>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              ))}
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

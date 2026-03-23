"use client";

import { useEffect, useState, useCallback } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { UserMenu } from "@/components/auth/user-menu";
import type { Scan } from "@/types/scan";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

const GRADE_COLORS: Record<string, string> = {
  A: "text-green-600",
  B: "text-lime-600",
  C: "text-yellow-600",
  D: "text-orange-600",
  F: "text-red-600",
};

const STATUS_BADGE: Record<string, "default" | "secondary" | "destructive" | "outline"> = {
  completed: "default",
  failed: "destructive",
  queued: "outline",
  cloning: "secondary",
  analyzing: "secondary",
  generating_report: "secondary",
};

export default function DashboardPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchScans = useCallback(async () => {
    try {
      const res = await fetch(`${API}/api/dashboard/scans`);
      if (res.ok) {
        const data = await res.json();
        setScans(data);
      }
    } catch {
      // API might not be running
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchScans();
    const interval = setInterval(fetchScans, 5000);
    return () => clearInterval(interval);
  }, [fetchScans]);

  return (
    <div className="min-h-screen">
      {/* Header */}
      <header className="border-b border-border/40 bg-background/95 backdrop-blur">
        <div className="container mx-auto flex h-14 items-center px-4">
          <a href="/" className="flex items-center gap-2 font-bold text-lg">
            <span className="text-primary">Repolyze</span>
            <span className="text-muted-foreground">AI</span>
          </a>
          <nav className="ml-auto flex items-center gap-4 text-sm">
            <span className="text-foreground font-medium">Dashboard</span>
            <UserMenu />
          </nav>
        </div>
      </header>

      <div className="container mx-auto max-w-5xl p-6 space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold">Scan History</h1>
          <a href="/">
            <Button>New Scan</Button>
          </a>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <Card>
            <CardContent className="pt-4 text-center">
              <p className="text-3xl font-bold">{scans.length}</p>
              <p className="text-xs text-muted-foreground">Total Scans</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4 text-center">
              <p className="text-3xl font-bold">
                {scans.reduce((sum, s) => sum + (s.total_findings || 0), 0)}
              </p>
              <p className="text-xs text-muted-foreground">Total Findings</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4 text-center">
              <p className="text-3xl font-bold text-red-600">
                {scans.reduce((sum, s) => sum + (s.critical_count || 0), 0)}
              </p>
              <p className="text-xs text-muted-foreground">Critical Issues</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4 text-center">
              <p className="text-3xl font-bold">
                {scans.filter((s) => s.agents_detected && s.agents_detected.length > 0).length}
              </p>
              <p className="text-xs text-muted-foreground">Agent Repos</p>
            </CardContent>
          </Card>
        </div>

        <Separator />

        {/* Scan List */}
        {loading ? (
          <p className="text-center text-muted-foreground py-8">Loading...</p>
        ) : scans.length === 0 ? (
          <Card>
            <CardContent className="py-12 text-center">
              <p className="text-muted-foreground mb-4">No scans yet</p>
              <a href="/">
                <Button>Run Your First Scan</Button>
              </a>
            </CardContent>
          </Card>
        ) : (
          <div className="space-y-3">
            {scans.map((scan) => (
              <a key={scan.id} href={`/scan/${scan.id}`} className="block">
                <Card className="hover:bg-muted/50 transition-colors cursor-pointer">
                  <CardContent className="py-4">
                    <div className="flex items-center justify-between">
                      <div className="space-y-1">
                        <div className="flex items-center gap-3">
                          <p className="font-semibold">{scan.repo_name}</p>
                          <Badge variant={STATUS_BADGE[scan.status] || "outline"}>
                            {scan.status}
                          </Badge>
                        </div>
                        <div className="flex items-center gap-3 text-xs text-muted-foreground">
                          <span>{new Date(scan.created_at).toLocaleDateString()}</span>
                          {scan.languages_detected && (
                            <span>{scan.languages_detected.join(", ")}</span>
                          )}
                          {scan.agents_detected && scan.agents_detected.length > 0 && (
                            <Badge variant="secondary" className="text-xs">
                              {scan.agents_detected.join(", ")}
                            </Badge>
                          )}
                          {scan.mcp_detected && (
                            <Badge variant="secondary" className="text-xs">MCP</Badge>
                          )}
                        </div>
                      </div>

                      <div className="flex items-center gap-6 text-right">
                        {scan.status === "completed" && (
                          <>
                            <div>
                              <p className="text-lg font-bold">{scan.total_findings}</p>
                              <p className="text-xs text-muted-foreground">findings</p>
                            </div>
                            {scan.critical_count > 0 && (
                              <div>
                                <p className="text-lg font-bold text-red-600">{scan.critical_count}</p>
                                <p className="text-xs text-muted-foreground">critical</p>
                              </div>
                            )}
                            {scan.agent_safety_grade && (
                              <div>
                                <p className={`text-2xl font-bold ${GRADE_COLORS[scan.agent_safety_grade] || ""}`}>
                                  {scan.agent_safety_grade}
                                </p>
                                <p className="text-xs text-muted-foreground">grade</p>
                              </div>
                            )}
                          </>
                        )}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </a>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

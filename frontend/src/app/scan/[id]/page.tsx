"use client";

import { useEffect, useState, useCallback } from "react";
import { useParams } from "next/navigation";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { getScan, getFindings } from "@/lib/api";
import { FindingsTable } from "@/components/report/findings-table";
import { SummaryCards } from "@/components/report/summary-cards";
import type { Scan, Finding } from "@/types/scan";

const STATUS_LABELS: Record<string, string> = {
  queued: "Queued",
  cloning: "Cloning repository...",
  analyzing: "Running security analysis...",
  generating_report: "Generating report...",
  completed: "Scan complete",
  failed: "Scan failed",
};

export default function ScanPage() {
  const params = useParams();
  const scanId = params.id as string;
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<readonly Finding[]>([]);
  const [error, setError] = useState("");

  const fetchScan = useCallback(async () => {
    try {
      const data = await getScan(scanId);
      setScan(data);
      if (data.status === "completed") {
        const f = await getFindings(scanId);
        setFindings(f);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load scan");
    }
  }, [scanId]);

  useEffect(() => {
    fetchScan();
    const isActive = (s: Scan | null) =>
      s && !["completed", "failed"].includes(s.status);

    const interval = setInterval(() => {
      if (isActive(scan)) fetchScan();
    }, 3000);

    return () => clearInterval(interval);
  }, [fetchScan, scan]);

  if (error) {
    return (
      <div className="flex-1 flex items-center justify-center p-8">
        <Card className="max-w-md w-full">
          <CardContent className="pt-6 text-center text-destructive">
            {error}
          </CardContent>
        </Card>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="flex-1 flex items-center justify-center p-8">
        <p className="text-muted-foreground">Loading scan...</p>
      </div>
    );
  }

  const isRunning = !["completed", "failed"].includes(scan.status);

  return (
    <div className="container mx-auto max-w-5xl p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">{scan.repo_name}</h1>
          <p className="text-sm text-muted-foreground">{scan.repo_url}</p>
        </div>
        <Badge variant={scan.status === "completed" ? "default" : scan.status === "failed" ? "destructive" : "secondary"}>
          {STATUS_LABELS[scan.status] ?? scan.status}
        </Badge>
      </div>

      {/* Progress */}
      {isRunning && (
        <Card>
          <CardContent className="pt-6 space-y-3">
            <div className="flex justify-between text-sm">
              <span>{scan.current_step || STATUS_LABELS[scan.status]}</span>
              <span>{scan.progress}%</span>
            </div>
            <Progress value={scan.progress} />
          </CardContent>
        </Card>
      )}

      {/* Detection badges */}
      {(scan.languages_detected || scan.agents_detected || scan.mcp_detected) && (
        <div className="flex flex-wrap gap-2">
          {scan.languages_detected?.map((lang) => (
            <Badge key={lang} variant="outline">{lang}</Badge>
          ))}
          {scan.agents_detected?.map((agent) => (
            <Badge key={agent} variant="secondary">{agent} detected</Badge>
          ))}
          {scan.mcp_detected && (
            <Badge variant="secondary">MCP Server detected</Badge>
          )}
        </div>
      )}

      {/* Results */}
      {scan.status === "completed" && (
        <>
          <SummaryCards scan={scan} />
          <Separator />

          <div className="flex items-center justify-between">
            <h2 className="text-xl font-semibold">Findings</h2>
            <a href={`${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/api/scans/${scan.id}/reports/latest/download`} target="_blank" rel="noopener noreferrer">
              <Button variant="outline" size="sm">
                Download PDF
              </Button>
            </a>
          </div>

          <FindingsTable findings={findings} />
        </>
      )}

      {scan.status === "failed" && scan.error_message && (
        <Card>
          <CardHeader>
            <CardTitle className="text-destructive">Scan Failed</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">{scan.error_message}</p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

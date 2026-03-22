"use client";

import { useState } from "react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import type { Finding, Severity } from "@/types/scan";

interface FindingsTableProps {
  readonly findings: readonly Finding[];
}

const SEVERITY_VARIANT: Record<Severity, "destructive" | "default" | "secondary" | "outline"> = {
  CRITICAL: "destructive",
  HIGH: "destructive",
  MEDIUM: "default",
  LOW: "secondary",
  INFO: "outline",
};

const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

export function FindingsTable({ findings }: FindingsTableProps) {
  const [filter, setFilter] = useState<Severity | "ALL">("ALL");

  const filtered = filter === "ALL"
    ? findings
    : findings.filter((f) => f.severity === filter);

  const sorted = [...filtered].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
  );

  return (
    <div className="space-y-4">
      {/* Filter buttons */}
      <div className="flex gap-2 flex-wrap">
        {(["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const).map((sev) => (
          <Badge
            key={sev}
            variant={filter === sev ? "default" : "outline"}
            className="cursor-pointer"
            onClick={() => setFilter(sev)}
          >
            {sev} {sev !== "ALL" && `(${findings.filter((f) => f.severity === sev).length})`}
          </Badge>
        ))}
      </div>

      {/* Table */}
      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-24">Severity</TableHead>
              <TableHead>Title</TableHead>
              <TableHead className="w-48">File</TableHead>
              <TableHead className="w-24">Tool</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {sorted.length === 0 ? (
              <TableRow>
                <TableCell colSpan={4} className="text-center text-muted-foreground py-8">
                  No findings
                </TableCell>
              </TableRow>
            ) : (
              sorted.map((finding) => (
                <TableRow key={finding.id}>
                  <TableCell>
                    <Badge variant={SEVERITY_VARIANT[finding.severity]}>
                      {finding.severity}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <p className="font-medium text-sm">{finding.title}</p>
                    <p className="text-xs text-muted-foreground line-clamp-1">
                      {finding.description}
                    </p>
                  </TableCell>
                  <TableCell className="text-xs font-mono text-muted-foreground">
                    {finding.file_path}
                    {finding.line_start && `:${finding.line_start}`}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {finding.tool_name || finding.agent_name}
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}

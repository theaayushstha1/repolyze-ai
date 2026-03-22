import type { Scan, Finding, AgentFinding, ScanCreate } from "@/types/scan";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...options?.headers },
    ...options,
  });

  if (!res.ok) {
    const data = await res.json().catch(() => null);
    throw new Error(data?.detail || `API error: ${res.status}`);
  }

  return res.json();
}

export function createScan(data: ScanCreate): Promise<Scan> {
  return apiFetch<Scan>("/api/scans", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export function getScan(scanId: string): Promise<Scan> {
  return apiFetch<Scan>(`/api/scans/${scanId}`);
}

export function getFindings(scanId: string): Promise<readonly Finding[]> {
  return apiFetch<readonly Finding[]>(`/api/scans/${scanId}/findings`);
}

export function getAgentFindings(scanId: string): Promise<readonly AgentFinding[]> {
  return apiFetch<readonly AgentFinding[]>(`/api/scans/${scanId}/agent-findings`);
}

export function generateReport(scanId: string): Promise<{ id: string }> {
  return apiFetch<{ id: string }>(`/api/scans/${scanId}/reports`, {
    method: "POST",
  });
}

export function getReportDownloadUrl(scanId: string, reportId: string): string {
  return `${API_BASE}/api/scans/${scanId}/reports/${reportId}/download`;
}

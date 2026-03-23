import type { Scan, Finding, AgentFinding, ScanCreate } from "@/types/scan";
import { getAccessToken } from "@/lib/supabase/auth";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  // Attach auth token if available
  try {
    const token = await getAccessToken();
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
  } catch {
    // Auth not available, continue anonymously
  }

  const res = await fetch(`${API_BASE}${path}`, {
    headers: { ...headers, ...options?.headers },
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

export function getQuota(): Promise<{
  plan: string;
  monthly_limit: number;
  scans_used: number;
  scans_remaining: number;
}> {
  return apiFetch("/api/auth/quota");
}

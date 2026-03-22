export type ScanStatus =
  | "queued"
  | "cloning"
  | "analyzing"
  | "generating_report"
  | "completed"
  | "failed";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface Scan {
  readonly id: string;
  readonly repo_url: string;
  readonly repo_name: string;
  readonly branch: string;
  readonly commit_sha: string | null;
  readonly status: ScanStatus;
  readonly progress: number;
  readonly current_step: string | null;
  readonly languages_detected: readonly string[] | null;
  readonly agents_detected: readonly string[] | null;
  readonly mcp_detected: boolean;
  readonly total_findings: number;
  readonly critical_count: number;
  readonly high_count: number;
  readonly medium_count: number;
  readonly low_count: number;
  readonly info_count: number;
  readonly agent_safety_grade: string | null;
  readonly scan_duration_ms: number | null;
  readonly error_message: string | null;
  readonly created_at: string;
  readonly completed_at: string | null;
}

export interface Finding {
  readonly id: string;
  readonly scan_id: string;
  readonly agent_name: string;
  readonly tool_name: string | null;
  readonly category: string;
  readonly severity: Severity;
  readonly confidence: string;
  readonly title: string;
  readonly description: string;
  readonly file_path: string | null;
  readonly line_start: number | null;
  readonly line_end: number | null;
  readonly code_snippet: string | null;
  readonly cwe_id: string | null;
  readonly cve_id: string | null;
  readonly remediation: string | null;
}

export interface AgentFinding extends Finding {
  readonly test_type: string;
  readonly prompt_used: string;
  readonly response: string;
  readonly pass_fail: "pass" | "fail";
  readonly risk_level: string;
}

export interface FindingSummary {
  readonly total: number;
  readonly critical: number;
  readonly high: number;
  readonly medium: number;
  readonly low: number;
  readonly info: number;
}

export interface ScanCreate {
  readonly repo_url: string;
  readonly branch?: string;
}

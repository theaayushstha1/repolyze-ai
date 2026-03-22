-- RepolyzeAI Initial Schema
-- Version: 1.0
-- Date: 2026-03-22

-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================
-- PROFILES (extends Supabase Auth)
-- ============================================================
CREATE TABLE profiles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email TEXT NOT NULL,
    display_name TEXT,
    github_username TEXT,
    github_access_token TEXT,
    plan TEXT NOT NULL DEFAULT 'free',
    scans_remaining INTEGER NOT NULL DEFAULT 10,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- SCANS
-- ============================================================
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES profiles(id),
    repo_url TEXT NOT NULL,
    repo_name TEXT NOT NULL,
    branch TEXT NOT NULL DEFAULT 'main',
    commit_sha TEXT,
    status TEXT NOT NULL DEFAULT 'queued',
    progress INTEGER NOT NULL DEFAULT 0,
    current_step TEXT,
    languages_detected JSONB,
    agents_detected JSONB,
    mcp_detected BOOLEAN NOT NULL DEFAULT FALSE,
    total_findings INTEGER NOT NULL DEFAULT 0,
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count INTEGER NOT NULL DEFAULT 0,
    medium_count INTEGER NOT NULL DEFAULT 0,
    low_count INTEGER NOT NULL DEFAULT 0,
    info_count INTEGER NOT NULL DEFAULT 0,
    agent_safety_grade TEXT,
    scan_duration_ms INTEGER,
    error_message TEXT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- FINDINGS (code security)
-- ============================================================
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    agent_name TEXT NOT NULL,
    tool_name TEXT,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL DEFAULT 'medium',
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    file_path TEXT,
    line_start INTEGER,
    line_end INTEGER,
    code_snippet TEXT,
    cwe_id TEXT,
    cve_id TEXT,
    remediation TEXT,
    reference_urls JSONB,
    is_false_positive BOOLEAN NOT NULL DEFAULT FALSE,
    is_duplicate BOOLEAN NOT NULL DEFAULT FALSE,
    duplicate_of UUID REFERENCES findings(id),
    raw_output JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- AGENT FINDINGS (AI agent safety)
-- ============================================================
CREATE TABLE agent_findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    agent_name TEXT NOT NULL,
    test_type TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    prompt_used TEXT,
    response TEXT,
    pass_fail TEXT NOT NULL DEFAULT 'fail',
    risk_level TEXT NOT NULL DEFAULT 'medium',
    owasp_category TEXT,
    remediation TEXT,
    raw_output JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- REPORTS
-- ============================================================
CREATE TABLE reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    report_type TEXT NOT NULL DEFAULT 'full',
    pdf_storage_path TEXT,
    pdf_size_bytes INTEGER,
    html_content TEXT,
    summary JSONB,
    generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- API KEYS
-- ============================================================
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES profiles(id),
    key_hash TEXT NOT NULL,
    key_prefix TEXT NOT NULL,
    name TEXT NOT NULL,
    scopes JSONB NOT NULL DEFAULT '["scan:create", "scan:read", "report:read"]',
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- INDEXES
-- ============================================================
CREATE INDEX idx_scans_user_id ON scans(user_id);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_repo_url ON scans(repo_url);
CREATE INDEX idx_scans_created_at ON scans(created_at DESC);
CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_category ON findings(category);
CREATE INDEX idx_agent_findings_scan_id ON agent_findings(scan_id);
CREATE INDEX idx_agent_findings_test_type ON agent_findings(test_type);
CREATE INDEX idx_reports_scan_id ON reports(scan_id);
CREATE INDEX idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX idx_api_keys_key_prefix ON api_keys(key_prefix);

-- ============================================================
-- ROW LEVEL SECURITY (RLS)
-- ============================================================

-- Enable RLS on all tables
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;

-- Profiles: users can only read/update their own profile
CREATE POLICY profiles_select_own ON profiles
    FOR SELECT USING (auth.uid() = id);

CREATE POLICY profiles_update_own ON profiles
    FOR UPDATE USING (auth.uid() = id)
    WITH CHECK (auth.uid() = id);

CREATE POLICY profiles_insert_own ON profiles
    FOR INSERT WITH CHECK (auth.uid() = id);

-- Scans: users can only access their own scans
CREATE POLICY scans_select_own ON scans
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY scans_insert_own ON scans
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY scans_update_own ON scans
    FOR UPDATE USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY scans_delete_own ON scans
    FOR DELETE USING (auth.uid() = user_id);

-- Findings: users can access findings for their own scans
CREATE POLICY findings_select_own ON findings
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM scans
            WHERE scans.id = findings.scan_id
            AND scans.user_id = auth.uid()
        )
    );

CREATE POLICY findings_insert_service ON findings
    FOR INSERT WITH CHECK (
        EXISTS (
            SELECT 1 FROM scans
            WHERE scans.id = findings.scan_id
            AND scans.user_id = auth.uid()
        )
    );

-- Agent Findings: users can access agent findings for their own scans
CREATE POLICY agent_findings_select_own ON agent_findings
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM scans
            WHERE scans.id = agent_findings.scan_id
            AND scans.user_id = auth.uid()
        )
    );

CREATE POLICY agent_findings_insert_service ON agent_findings
    FOR INSERT WITH CHECK (
        EXISTS (
            SELECT 1 FROM scans
            WHERE scans.id = agent_findings.scan_id
            AND scans.user_id = auth.uid()
        )
    );

-- Reports: users can access reports for their own scans
CREATE POLICY reports_select_own ON reports
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM scans
            WHERE scans.id = reports.scan_id
            AND scans.user_id = auth.uid()
        )
    );

CREATE POLICY reports_insert_service ON reports
    FOR INSERT WITH CHECK (
        EXISTS (
            SELECT 1 FROM scans
            WHERE scans.id = reports.scan_id
            AND scans.user_id = auth.uid()
        )
    );

-- API Keys: users can only manage their own API keys
CREATE POLICY api_keys_select_own ON api_keys
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY api_keys_insert_own ON api_keys
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY api_keys_update_own ON api_keys
    FOR UPDATE USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY api_keys_delete_own ON api_keys
    FOR DELETE USING (auth.uid() = user_id);

-- ============================================================
-- UPDATED_AT TRIGGER
-- ============================================================
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER set_profiles_updated_at
    BEFORE UPDATE ON profiles
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

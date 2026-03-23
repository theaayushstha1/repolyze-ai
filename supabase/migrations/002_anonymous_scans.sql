-- Allow anonymous scans (user_id = NULL) for free tier
-- The backend uses service_role_key which bypasses RLS,
-- but this migration adds anon-friendly policies for when
-- we want to allow unauthenticated frontend reads.

-- Allow anyone to read scans with no user_id (anonymous/demo scans)
CREATE POLICY scans_select_anonymous ON scans
    FOR SELECT USING (user_id IS NULL);

-- Allow anyone to read findings for anonymous scans
CREATE POLICY findings_select_anonymous ON findings
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM scans
            WHERE scans.id = findings.scan_id
            AND scans.user_id IS NULL
        )
    );

-- Allow anyone to read agent findings for anonymous scans
CREATE POLICY agent_findings_select_anonymous ON agent_findings
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM scans
            WHERE scans.id = agent_findings.scan_id
            AND scans.user_id IS NULL
        )
    );

-- Allow anyone to read reports for anonymous scans
CREATE POLICY reports_select_anonymous ON reports
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM scans
            WHERE scans.id = reports.scan_id
            AND scans.user_id IS NULL
        )
    );

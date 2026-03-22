"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

const GITHUB_URL_REGEX = /^https:\/\/github\.com\/[\w.-]+\/[\w.-]+\/?$/;

export function ScanForm() {
  const [url, setUrl] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const router = useRouter();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    const trimmed = url.trim();
    if (!trimmed) {
      setError("Please enter a GitHub repository URL");
      return;
    }

    if (!GITHUB_URL_REGEX.test(trimmed)) {
      setError("Please enter a valid GitHub URL (https://github.com/owner/repo)");
      return;
    }

    setLoading(true);
    try {
      const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/api/scans`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo_url: trimmed }),
      });

      if (!res.ok) {
        const data = await res.json().catch(() => null);
        throw new Error(data?.detail || `Scan failed (${res.status})`);
      }

      const scan = await res.json();
      router.push(`/scan/${scan.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to start scan");
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="w-full max-w-xl mx-auto space-y-3">
      <div className="flex gap-2">
        <Input
          type="url"
          placeholder="https://github.com/owner/repo"
          value={url}
          onChange={(e) => {
            setUrl(e.target.value);
            if (error) setError("");
          }}
          className="h-12 text-base"
          disabled={loading}
        />
        <Button type="submit" size="lg" className="h-12 px-8" disabled={loading}>
          {loading ? "Starting..." : "Scan"}
        </Button>
      </div>
      {error && (
        <p className="text-sm text-destructive text-left">{error}</p>
      )}
    </form>
  );
}

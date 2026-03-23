"use client";

import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { getUser, signInWithGitHub, signOut } from "@/lib/supabase/auth";
import { isSupabaseConfigured } from "@/lib/supabase/client";
import type { User } from "@supabase/supabase-js";

export function UserMenu() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const configured = isSupabaseConfigured();

  useEffect(() => {
    if (!configured) {
      setLoading(false);
      return;
    }

    getUser().then((u) => {
      setUser(u);
      setLoading(false);
    });
  }, [configured]);

  if (!configured) {
    return (
      <span className="text-xs text-muted-foreground">Demo Mode</span>
    );
  }

  if (loading) return null;

  if (user) {
    const name =
      user.user_metadata?.preferred_username ||
      user.user_metadata?.user_name ||
      user.email ||
      "User";

    return (
      <div className="flex items-center gap-3">
        <span className="text-sm">{name}</span>
        <Button
          variant="outline"
          size="sm"
          onClick={async () => {
            await signOut();
            setUser(null);
          }}
        >
          Sign out
        </Button>
      </div>
    );
  }

  return (
    <Button
      variant="outline"
      size="sm"
      onClick={() => signInWithGitHub()}
    >
      Sign in with GitHub
    </Button>
  );
}

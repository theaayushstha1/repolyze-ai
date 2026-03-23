"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { isSupabaseConfigured, createClient } from "@/lib/supabase/client";

export default function AuthCallbackPage() {
  const router = useRouter();

  useEffect(() => {
    if (!isSupabaseConfigured()) {
      router.replace("/dashboard");
      return;
    }

    const supabase = createClient();
    supabase.auth.onAuthStateChange((event) => {
      if (event === "SIGNED_IN") {
        router.replace("/dashboard");
      }
    });
  }, [router]);

  return (
    <div className="flex-1 flex items-center justify-center p-8">
      <p className="text-muted-foreground">Signing in...</p>
    </div>
  );
}

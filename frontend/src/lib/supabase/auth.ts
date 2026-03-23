"use client";

import { createClient, isSupabaseConfigured } from "./client";
import type { User } from "@supabase/supabase-js";

export async function signInWithGitHub() {
  if (!isSupabaseConfigured()) {
    console.warn("Supabase not configured, auth disabled");
    return null;
  }

  const supabase = createClient();
  const { data, error } = await supabase.auth.signInWithOAuth({
    provider: "github",
    options: {
      redirectTo: `${window.location.origin}/auth/callback`,
    },
  });

  if (error) throw error;
  return data;
}

export async function signOut() {
  if (!isSupabaseConfigured()) return;

  const supabase = createClient();
  await supabase.auth.signOut();
}

export async function getUser(): Promise<User | null> {
  if (!isSupabaseConfigured()) return null;

  const supabase = createClient();
  const { data } = await supabase.auth.getUser();
  return data.user;
}

export async function getSession() {
  if (!isSupabaseConfigured()) return null;

  const supabase = createClient();
  const { data } = await supabase.auth.getSession();
  return data.session;
}

export async function getAccessToken(): Promise<string | null> {
  const session = await getSession();
  return session?.access_token ?? null;
}

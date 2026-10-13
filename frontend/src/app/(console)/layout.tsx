"use client";

import type { ReactNode } from "react";
import { useApi, type Me, type Meta } from "@/lib/api";
import { SessionContext } from "@/components/session";
import { Shell } from "@/components/shell";
import { Spinner, ToastProvider } from "@/components/ui";

export default function ConsoleLayout({ children }: { children: ReactNode }) {
  const { data: me, error } = useApi<Me>("/auth/me");
  const { data: meta } = useApi<Meta>(me ? "/meta" : null);

  if (error && error.status !== 401) {
    return <div className="flex min-h-screen items-center justify-center px-6 text-center text-sm text-muted">The API is not reachable right now ({error.message}). It may still be starting.</div>;
  }
  if (!me || !meta) return <div className="flex min-h-screen items-center justify-center"><Spinner /></div>;

  const session = { me, meta, canWrite: me.role !== "viewer", isAdmin: me.role === "admin" };
  return (
    <SessionContext.Provider value={session}>
      <ToastProvider>
        <Shell>{children}</Shell>
      </ToastProvider>
    </SessionContext.Provider>
  );
}

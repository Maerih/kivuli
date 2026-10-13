"use client";

import { createContext, useContext } from "react";
import type { Me, Meta } from "@/lib/api";

export interface Session { me: Me; meta: Meta; canWrite: boolean; isAdmin: boolean }

export const SessionContext = createContext<Session | null>(null);

export function useSession(): Session {
  const session = useContext(SessionContext);
  if (!session) throw new Error("useSession must be used inside the console layout");
  return session;
}

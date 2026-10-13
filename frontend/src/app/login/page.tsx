"use client";

import { ShieldCheck } from "lucide-react";
import { useState, type FormEvent } from "react";
import { api } from "@/lib/api";
import { Button, Field } from "@/components/ui";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [needsCode, setNeedsCode] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api("/auth/login", { method: "POST", body: { email, password, ...(needsCode ? { code: code.trim() } : {}) } });
      const next = new URLSearchParams(window.location.search).get("next");
      // Only ever redirect to a path on this site.
      window.location.href = next && next.startsWith("/") && !next.startsWith("//") ? next : "/";
    } catch (err) {
      // The password was right and this account has a second factor: ask for it without an error.
      if (err instanceof Error && err.message === "mfa_required") setNeedsCode(true);
      else setError(err instanceof Error ? err.message : "Sign-in failed");
      setBusy(false);
    }
  };

  return (
    <main className="flex min-h-screen items-center justify-center px-4">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex items-center gap-3">
          <span className="flex h-10 w-10 items-center justify-center rounded-lg bg-ink text-page"><ShieldCheck className="h-5 w-5" /></span>
          <div>
            <h1 className="text-lg font-semibold leading-tight">Kivuli</h1>
            <p className="text-sm text-muted">Dark web threat intelligence</p>
          </div>
        </div>
        <form onSubmit={submit} className="card space-y-4 p-5">
          <Field label="Email">
            <input className="field" type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} />
          </Field>
          <Field label="Password">
            <input className="field" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
          </Field>
          {needsCode && (
            <Field label="Verification code" hint="The 6-digit code from your authenticator app, or one of your recovery codes.">
              <input className="field font-mono tracking-widest" inputMode="text" autoComplete="one-time-code" autoFocus required value={code} onChange={(e) => setCode(e.target.value)} />
            </Field>
          )}
          {error && <p className="rounded-md bg-critical-soft px-3 py-2 text-sm text-critical" role="alert">{error}</p>}
          <Button variant="primary" busy={busy} className="w-full" type="submit">{needsCode ? "Verify and sign in" : "Sign in"}</Button>
        </form>
        <p className="mt-4 text-center text-xs text-muted">Authorised analysts only. All activity is recorded in the audit log.</p>
      </div>
    </main>
  );
}

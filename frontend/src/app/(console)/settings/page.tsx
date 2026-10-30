"use client";

import { CheckCircle2, Mail, Plus, Send, ShieldCheck, XCircle } from "lucide-react";
import { useState } from "react";
import { PageHeader } from "@/components/shell";
import { useSession } from "@/components/session";
import { Badge, Button, Card, CardHeader, CopyButton, Empty, ErrorNote, Field, Modal, Pagination, Spinner, Tabs, useAction } from "@/components/ui";
import { api, qs, useApi } from "@/lib/api";
import { ago, num, pct, stamp, titleCase } from "@/lib/format";

interface Health {
  database: { ok: boolean; findings?: number; error?: string };
  search: { ok: boolean; status?: string; indexed?: number; error?: string };
  queue: { ok: boolean; crawl?: number; pipeline?: number; notify?: number; enrich?: number; error?: string };
  quality?: { findings: number; verification: Record<string, number>; duplicates: number; unclassified: number; duplicate_rate: number; unclassified_rate: number };
  attack?: { version: string; techniques: number; groups?: number; software?: number };
  tor: { ok: boolean; is_tor?: boolean; exit_ip?: string; latency_ms?: number; error?: string; checked_at?: string };
  email_backoff?: boolean;
  crawl: { last_fetch: string | null; fetches_24h: number; ok_24h: number; new_findings_24h: number };
  email: { enabled: boolean; smtp_host: string; smtp_port: number; test_inbox_port?: number; tls: string; from: string; default_recipients: string[]; authenticated: boolean };
  policy: { redact_secrets: boolean; store_raw_evidence: boolean; egress_allow_hosts: string[]; discover_onion_links: boolean; max_bytes: number; host_delay_seconds: number };
}
interface EmailRow { id: number; ts: string; kind: string; recipients: string[]; subject: string; alert_count: number; ok: boolean; error: string }
interface UserRow { id: number; email: string; name: string; role: string; is_active: boolean; last_login_at: string | null; locked: boolean; mfa_enabled?: boolean }
interface AuditRow { id: number; ts: string; user: string; action: string; object_type: string; object_id: string; ip: string; detail: Record<string, unknown> }

function State({ ok, children }: { ok: boolean; children: React.ReactNode }) {
  return <Badge tone={ok ? "good" : "critical"}>{ok ? <CheckCircle2 className="h-3 w-3" /> : <XCircle className="h-3 w-3" />}{children}</Badge>;
}
function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return <div className="flex items-start justify-between gap-4 border-b border-line px-4 py-2.5 text-sm last:border-b-0"><span className="shrink-0 text-ink-2">{label}</span><span className="min-w-0 text-right">{children}</span></div>;
}

function HealthTab() {
  const { data: h, error } = useApi<Health>("/system/health", { refreshInterval: 15000 });
  const { meta } = useSession();
  if (error) return <ErrorNote error={error} />;
  if (!h) return <Spinner />;
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card>
        <CardHeader title="Services" />
        <Row label="Database"><State ok={h.database.ok}>{h.database.ok ? `${num(h.database.findings ?? 0)} findings` : h.database.error}</State></Row>
        <Row label="Search index"><State ok={h.search.ok}>{h.search.ok ? `${num(h.search.indexed ?? 0)} indexed · ${h.search.status}` : h.search.error}</State></Row>
        <Row label="Work queues"><State ok={h.queue.ok}>{h.queue.ok ? `crawl ${h.queue.crawl} · pipeline ${h.queue.pipeline} · email ${h.queue.notify}${h.queue.enrich !== undefined ? ` · enrichment ${h.queue.enrich}` : ""}` : h.queue.error}</State></Row>
        <Row label="Tor gateway">
          <State ok={Boolean(h.tor.ok && h.tor.is_tor)}>{h.tor.ok ? (h.tor.is_tor ? "Exiting through Tor" : "NOT exiting through Tor") : "Not ready"}</State>
          <div className="mt-1 text-xs text-muted">{h.tor.ok ? `Exit ${h.tor.exit_ip} · ${((h.tor.latency_ms ?? 0) / 1000).toFixed(1)} s · checked ${ago(h.tor.checked_at)}` : h.tor.error}</div>
        </Row>
      </Card>
      <Card>
        <CardHeader title="Collection, last 24 hours" />
        <Row label="Fetches">{num(h.crawl.fetches_24h)} <span className="text-muted">({num(h.crawl.ok_24h)} succeeded)</span></Row>
        <Row label="New findings">{num(h.crawl.new_findings_24h)}</Row>
        <Row label="Last fetch">{h.crawl.last_fetch ? ago(h.crawl.last_fetch) : "none yet"}</Row>
      </Card>
      {h.quality && (
        <Card className="lg:col-span-2">
          <CardHeader title="Intelligence quality" hint="How much of what is collected has been corroborated, and how much is noise" />
          <div className="grid gap-x-8 sm:grid-cols-2">
            <div>
              {["confirmed", "corroborated", "reported", "unverified"].map((state) => (
                <Row key={state} label={meta.verification?.[state] ?? titleCase(state)}>{num(h.quality!.verification[state] ?? 0)} <span className="text-muted">({pct(h.quality!.findings ? (h.quality!.verification[state] ?? 0) / h.quality!.findings : 0, 0)})</span></Row>
              ))}
            </div>
            <div>
              <Row label="Duplicates suppressed">{num(h.quality.duplicates)} <span className="text-muted">({pct(h.quality.duplicate_rate, 0)})</span></Row>
              <Row label="Could not be classified">{num(h.quality.unclassified)} <span className="text-muted">({pct(h.quality.unclassified_rate, 0)})</span></Row>
              {h.attack && <Row label="ATT&CK catalogue">v{h.attack.version} <span className="text-muted">· {num(h.attack.techniques)} techniques</span></Row>}
            </div>
          </div>
        </Card>
      )}
      <Card className="lg:col-span-2">
        <CardHeader title="Collection policy" hint="Set in .env by the operator. The application cannot change these." />
        <Row label="Secrets in captured content">{h.policy.redact_secrets ? "Redacted before storage, indexing and email" : "Stored as captured"}</Row>
        <Row label="Unredacted raw captures">{h.policy.store_raw_evidence ? "Kept on the evidence volume" : "Not kept (hash only)"}</Row>
        <Row label="Newly seen onion links">{h.policy.discover_onion_links ? "Filed as candidates for analyst approval" : "Ignored"}</Row>
        <Row label="Fetch limits">{Math.round(h.policy.max_bytes / 1e6)} MB per page · {h.policy.host_delay_seconds} s between requests to one host · text only, GET only</Row>
        <Row label="Direct clearnet egress"><span className="break-all font-mono text-xs">{h.policy.egress_allow_hosts.join(", ") || "none"}</span></Row>
      </Card>
    </div>
  );
}

function EmailTab() {
  const { isAdmin, me } = useSession();
  const { data: h } = useApi<Health>("/system/health");
  const { data: log, mutate } = useApi<EmailRow[]>("/system/email-log", { refreshInterval: 10000 });
  const [to, setTo] = useState(me.email);
  const { busy, run } = useAction();
  if (!h) return <Spinner />;
  const local = h.email.smtp_host === "mailpit";
  return (
    <div className="grid gap-4 lg:grid-cols-[22rem_minmax(0,1fr)]">
      <div className="space-y-4">
        <Card>
          <CardHeader title="Delivery" />
          <Row label="Alert email"><State ok={h.email.enabled && !h.email_backoff}>{!h.email.enabled ? "Off" : h.email_backoff ? "Paused after an error" : "On"}</State></Row>
          <Row label="Relay"><span className="font-mono text-xs">{h.email.smtp_host}:{h.email.smtp_port}</span><div className="text-xs text-muted">{h.email.tls === "none" ? "no TLS" : h.email.tls.toUpperCase()}{h.email.authenticated ? " · authenticated" : ""}</div></Row>
          <Row label="From"><span className="break-all text-xs">{h.email.from}</span></Row>
          <Row label="Default recipients"><span className="break-all text-xs">{h.email.default_recipients.join(", ") || "none"}</span></Row>
        </Card>
        {local && (
          <div className="rounded-md border border-line bg-warning-soft px-3 py-2.5 text-sm">
            Mail is going to the bundled test inbox, not to real mailboxes. Open it at <a className="link" href={`http://localhost:${h.email.test_inbox_port ?? 28942}`} target="_blank" rel="noopener">localhost:{h.email.test_inbox_port ?? 28942}</a> on the server (through an SSH tunnel from elsewhere). To deliver for real, set SMTP_HOST, SMTP_PORT, SMTP_TLS, SMTP_USERNAME and SMTP_PASSWORD in <span className="font-mono">.env</span> and restart.
          </div>
        )}
        {isAdmin && (
          <Card>
            <CardHeader title="Send a test message" />
            <div className="space-y-3 p-4">
              <Field label="To"><input className="field" type="email" value={to} onChange={(e) => setTo(e.target.value)} /></Field>
              <Button variant="primary" busy={busy} onClick={() => run(() => api("/system/test-email", { method: "POST", body: { to } }), "Test message queued. The result appears in the log.").then(() => setTimeout(() => mutate(), 3000))}><Send className="h-3.5 w-3.5" /> Send test</Button>
            </div>
          </Card>
        )}
      </div>
      <Card>
        <CardHeader title="Email log" hint="The last 50 messages" />
        {!log ? <Spinner /> : log.length === 0 ? <Empty title="No email sent yet" hint="Messages are sent when a finding matches a watchlist entry with email turned on." /> : (
          <ul className="divide-y divide-line">
            {log.map((m) => (
              <li key={m.id} className="px-4 py-2.5">
                <div className="flex items-center gap-2"><State ok={m.ok}>{m.ok ? "Sent" : "Failed"}</State><Badge>{titleCase(m.kind)}</Badge><span className="ml-auto text-xs text-muted" title={stamp(m.ts)}>{ago(m.ts)}</span></div>
                <div className="mt-1 break-words text-sm">{m.subject}</div>
                <div className="text-xs text-muted"><Mail className="mr-1 inline h-3 w-3" />{m.recipients.join(", ")}{m.alert_count ? ` · ${m.alert_count} alert${m.alert_count === 1 ? "" : "s"}` : ""}</div>
                {m.error && <div className="mt-1 break-words text-xs text-critical">{m.error}</div>}
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}

function UsersTab() {
  const { me } = useSession();
  const { data, error, mutate } = useApi<UserRow[]>("/users");
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({ email: "", name: "", role: "analyst", password: "" });
  const { busy, run } = useAction();
  const create = async () => { if (await run(() => api("/users", { method: "POST", body: form }), "User created")) { setCreating(false); setForm({ email: "", name: "", role: "analyst", password: "" }); mutate(); } };
  const patch = (u: UserRow, body: Record<string, unknown>, message: string) => run(() => api(`/users/${u.id}`, { method: "PATCH", body }), message).then(() => mutate());
  const reset = (u: UserRow) => { const password = prompt(`New password for ${u.email} (12+ characters, mixed case and a digit):`); if (password) patch(u, { password }, "Password reset"); };
  if (error) return <ErrorNote error={error} />;
  return (
    <>
      <Card>
        <CardHeader title="Users" hint="Viewers read. Analysts triage, manage watchlists, sources and cases. Admins also manage users and see the audit log." action={<Button variant="primary" size="sm" onClick={() => setCreating(true)}><Plus className="h-3.5 w-3.5" /> Add user</Button>} />
        {!data ? <Spinner /> : (
          <div className="overflow-x-auto"><table className="w-full min-w-[640px]">
            <thead><tr className="border-b border-line"><th className="th">User</th><th className="th">Role</th><th className="th">Last sign-in</th><th className="th" /></tr></thead>
            <tbody className="divide-y divide-line">
              {data.map((u) => (
                <tr key={u.id} className={u.is_active ? "" : "opacity-60"}>
                  <td className="td"><div className="font-medium">{u.name || u.email}{u.id === me.id && <span className="ml-1.5 text-xs text-muted">(you)</span>}</div><div className="text-xs text-muted">{u.email}</div></td>
                  <td className="td">
                    <select aria-label={`Role for ${u.email}`} className="field h-8 w-28 px-2 text-xs" value={u.role} disabled={u.id === me.id} onChange={(e) => patch(u, { role: e.target.value }, "Role updated")}>
                      {["viewer", "analyst", "admin"].map((r) => <option key={r} value={r}>{titleCase(r)}</option>)}
                    </select>
                    {!u.is_active && <Badge className="ml-2">Disabled</Badge>}{u.locked && <Badge tone="warning" className="ml-2">Locked</Badge>}{u.mfa_enabled && <Badge tone="good" className="ml-2" title="Two-step sign-in is on"><ShieldCheck className="h-3 w-3" />MFA</Badge>}
                  </td>
                  <td className="td whitespace-nowrap text-xs text-muted">{ago(u.last_login_at)}</td>
                  <td className="td"><div className="flex justify-end gap-1">
                    <Button size="sm" onClick={() => reset(u)}>Reset password</Button>
                    {u.mfa_enabled && u.id !== me.id && <Button size="sm" title="For a user who lost their authenticator. They can enrol again after signing in." onClick={() => confirm(`Turn off two-step sign-in for ${u.email}?`) && patch(u, { reset_mfa: true }, "Two-step sign-in reset")}>Reset MFA</Button>}
                    {u.id !== me.id && <Button size="sm" variant={u.is_active ? "danger" : "secondary"} onClick={() => patch(u, { is_active: !u.is_active }, u.is_active ? "User disabled" : "User enabled")}>{u.is_active ? "Disable" : "Enable"}</Button>}
                  </div></td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
      </Card>
      <Modal open={creating} onClose={() => setCreating(false)} title="Add user" footer={<><Button onClick={() => setCreating(false)}>Cancel</Button><Button variant="primary" busy={busy} onClick={create}>Create user</Button></>}>
        <div className="space-y-4">
          <Field label="Email"><input className="field" type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></Field>
          <Field label="Name"><input className="field" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></Field>
          <Field label="Role"><select className="field" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>{["viewer", "analyst", "admin"].map((r) => <option key={r} value={r}>{titleCase(r)}</option>)}</select></Field>
          <Field label="Initial password" hint="At least 12 characters, with upper and lower case and a digit. Ask the user to change it after first sign-in."><input className="field font-mono" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /></Field>
        </div>
      </Modal>
    </>
  );
}

function AuditTab() {
  const [action, setAction] = useState("");
  const [who, setWho] = useState("");
  const [page, setPage] = useState(1);
  const { data, error } = useApi<{ total: number; items: AuditRow[] }>(`/audit${qs({ action, user_email: who, page, size: 100 })}`, { keepPreviousData: true });
  return (
    <>
      <Card>
        <CardHeader title="Audit log" hint="Sign-ins, exports, evidence views and every change, with the address they came from" action={<>
          <input className="field h-8 w-40 text-xs" placeholder="User" value={who} onChange={(e) => { setWho(e.target.value); setPage(1); }} aria-label="Filter by user" />
          <select className="field h-8 w-36 px-2 text-xs" value={action} onChange={(e) => { setAction(e.target.value); setPage(1); }} aria-label="Filter by action">
            <option value="">All actions</option>{["auth", "search", "evidence", "finding", "alert", "watchlist", "rule", "source", "case", "entity", "relationship", "indicator", "exposure", "asm", "integration", "provider", "apikey", "stix", "ai", "note", "user", "system"].map((a) => <option key={a} value={a}>{titleCase(a)}</option>)}
          </select></>} />
        <ErrorNote error={error} />
        {!data ? <Spinner /> : data.items.length === 0 ? <Empty title="No entries" /> : (
          <div className="overflow-x-auto"><table className="w-full min-w-[760px]">
            <thead><tr className="border-b border-line"><th className="th">When</th><th className="th">User</th><th className="th">Action</th><th className="th">Object</th><th className="th">Detail</th><th className="th">Address</th></tr></thead>
            <tbody className="divide-y divide-line">
              {data.items.map((r) => (
                <tr key={r.id}>
                  <td className="td whitespace-nowrap text-xs text-muted">{stamp(r.ts)}</td>
                  <td className="td text-xs">{r.user || <span className="text-muted">anonymous</span>}</td>
                  <td className="td whitespace-nowrap font-mono text-xs">{r.action}</td>
                  <td className="td whitespace-nowrap text-xs text-muted">{r.object_type}{r.object_id ? ` ${r.object_id.slice(0, 13)}` : ""}</td>
                  <td className="td max-w-xs text-xs text-muted"><span className="line-clamp-2 break-words">{Object.entries(r.detail ?? {}).map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`).join(" · ")}</span></td>
                  <td className="td whitespace-nowrap font-mono text-xs text-muted">{r.ip}</td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
      </Card>
      {data && <Pagination page={page} size={100} total={data.total} onPage={setPage} />}
    </>
  );
}

function MfaCard() {
  const { me } = useSession();
  const [enabled, setEnabled] = useState(Boolean(me.mfa_enabled));
  const [setup, setSetup] = useState<{ secret: string; uri: string; qr_svg: string } | null>(null);
  const [code, setCode] = useState("");
  const [recovery, setRecovery] = useState<string[] | null>(null);
  const [disabling, setDisabling] = useState(false);
  const [off, setOff] = useState({ password: "", code: "" });
  const { busy, run } = useAction();
  const begin = () => run(async () => { setSetup(await api("/auth/mfa/setup", { method: "POST" })); setCode(""); });
  const confirmCode = () => run(async () => {
    const out = await api<{ recovery_codes: string[] }>("/auth/mfa/enable", { method: "POST", body: { code: code.trim() } });
    setRecovery(out.recovery_codes); setSetup(null); setEnabled(true);
  }, "Two-step sign-in is on");
  const disable = async () => { if (await run(() => api("/auth/mfa/disable", { method: "POST", body: off }), "Two-step sign-in is off")) { setEnabled(false); setDisabling(false); setOff({ password: "", code: "" }); } };

  return (
    <Card className="max-w-md">
      <CardHeader title="Two-step sign-in" action={enabled ? <Badge tone="good"><ShieldCheck className="h-3 w-3" />On</Badge> : <Badge>Off</Badge>} />
      <div className="space-y-3 p-4 text-sm">
        {me.mfa_setup_required && !enabled && <p className="rounded-md bg-warning-soft px-3 py-2">This deployment requires two-step sign-in. Set it up now.</p>}
        {recovery ? (
          <>
            <p className="text-ink-2">Save these recovery codes somewhere safe. Each works once if you lose your authenticator, and they are not shown again.</p>
            <div className="grid grid-cols-2 gap-1 rounded-md border border-line bg-sunken p-3 font-mono text-xs">{recovery.map((c) => <span key={c}>{c}</span>)}</div>
            <div className="flex items-center gap-2"><Button size="sm" onClick={() => navigator.clipboard?.writeText(recovery.join("\n"))}>Copy all</Button><Button size="sm" variant="primary" onClick={() => setRecovery(null)}>I have saved them</Button></div>
          </>
        ) : setup ? (
          <>
            <p className="text-ink-2">Scan this with an authenticator app (Aegis, Google Authenticator, 1Password, Authy…), then enter the 6-digit code it shows.</p>
            {/* Shown as an image, so the SVG is never parsed into this page's DOM. */}
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img className="mx-auto h-44 w-44 rounded-md bg-white p-2" alt="QR code for your authenticator app" src={`data:image/svg+xml;charset=utf-8,${encodeURIComponent(setup.qr_svg)}`} />
            <div className="flex items-center gap-1 text-xs text-muted">Or enter the key by hand: <code className="break-all font-mono text-ink-2">{setup.secret}</code><CopyButton value={setup.secret} label="Copy key" /></div>
            <Field label="Code from the app"><input className="field font-mono tracking-widest" inputMode="numeric" autoComplete="one-time-code" maxLength={6} value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} /></Field>
            <div className="flex gap-2"><Button onClick={() => setSetup(null)}>Cancel</Button><Button variant="primary" busy={busy} disabled={code.length !== 6} onClick={confirmCode}>Turn on</Button></div>
          </>
        ) : enabled ? (
          disabling ? (
            <>
              <Field label="Password"><input className="field" type="password" autoComplete="current-password" value={off.password} onChange={(e) => setOff({ ...off, password: e.target.value })} /></Field>
              <Field label="Code from the app, or a recovery code"><input className="field font-mono" autoComplete="one-time-code" value={off.code} onChange={(e) => setOff({ ...off, code: e.target.value })} /></Field>
              <div className="flex gap-2"><Button onClick={() => setDisabling(false)}>Cancel</Button><Button variant="danger" busy={busy} disabled={!off.password || !off.code} onClick={disable}>Turn off</Button></div>
            </>
          ) : (
            <><p className="text-ink-2">Signing in needs your password and a code from your authenticator app.</p><Button size="sm" onClick={() => setDisabling(true)}>Turn off…</Button></>
          )
        ) : (
          <><p className="text-ink-2">Add a second step to sign-in: a time-based code from an authenticator app. A stolen password alone is then not enough to reach the intelligence held here.</p><Button variant="primary" busy={busy} onClick={begin}><ShieldCheck className="h-3.5 w-3.5" /> Set up</Button></>
        )}
      </div>
    </Card>
  );
}

function AccountTab() {
  const [form, setForm] = useState({ current_password: "", new_password: "" });
  const { busy, run } = useAction();
  return (
    <div className="grid items-start gap-4 lg:grid-cols-2">
      <Card className="max-w-md">
        <CardHeader title="Change your password" />
        <div className="space-y-4 p-4">
          <Field label="Current password"><input className="field" type="password" autoComplete="current-password" value={form.current_password} onChange={(e) => setForm({ ...form, current_password: e.target.value })} /></Field>
          <Field label="New password" hint="At least 12 characters, with upper and lower case and a digit."><input className="field" type="password" autoComplete="new-password" value={form.new_password} onChange={(e) => setForm({ ...form, new_password: e.target.value })} /></Field>
          <Button variant="primary" busy={busy} disabled={!form.current_password || !form.new_password} onClick={() => run(() => api("/auth/password", { method: "POST", body: form }), "Password changed").then((ok) => ok && setForm({ current_password: "", new_password: "" }))}>Change password</Button>
        </div>
      </Card>
      <MfaCard />
    </div>
  );
}

export default function SettingsPage() {
  const { isAdmin, canWrite } = useSession();
  const tabs = [
    ...(canWrite ? [{ id: "health", label: "Health" }, { id: "email", label: "Email alerts" }] : []),
    ...(isAdmin ? [{ id: "users", label: "Users" }, { id: "audit", label: "Audit log" }] : []),
    { id: "account", label: "My account" },
  ];
  const { me } = useSession();
  // An account that still has to enrol a second factor lands on the place to do it.
  const [tab, setTab] = useState(me.mfa_setup_required ? "account" : tabs[0].id);
  return (
    <>
      <PageHeader title="System" subtitle="Service health, intelligence quality, alert email, access control and the audit trail. Destinations, enrichment providers and API keys are under Integrations." />
      <div className="mb-4"><Tabs value={tab} onChange={setTab} tabs={tabs} /></div>
      {tab === "health" && <HealthTab />}
      {tab === "email" && <EmailTab />}
      {tab === "users" && <UsersTab />}
      {tab === "audit" && <AuditTab />}
      {tab === "account" && <AccountTab />}
    </>
  );
}

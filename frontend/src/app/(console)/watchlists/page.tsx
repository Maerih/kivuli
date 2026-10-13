"use client";

import { Building2, Mail, MailX, Plus, RefreshCw, Scan, Trash2 } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useState } from "react";
import { PageHeader } from "@/components/shell";
import { useSession } from "@/components/session";
import { Badge, Button, Card, Empty, ErrorNote, Field, Modal, Spinner, useAction } from "@/components/ui";
import { api, useApi } from "@/lib/api";
import { ago, titleCase, WATCH_LABELS } from "@/lib/format";

interface Watch {
  id: number; name: string; kind: string; value: string; description: string; is_active: boolean; min_severity: string;
  notify_mode: string; recipients: string[]; match_count: number; open_alerts: number; last_matched_at: string | null; created_at: string;
  is_asset: boolean; criticality: number; org: string; last_scanned_at: string | null;
}
// Kinds that can describe something the organisation owns, and the ones passive attack-surface discovery applies to.
const OWNABLE = ["domain", "email", "ip", "organization", "brand", "executive"];
const CRITICALITY = ["", "1 · Low", "2 · Minor", "3 · Normal", "4 · Important", "5 · Crown jewels"];
const BLANK = { name: "", kind: "domain", value: "", description: "", min_severity: "info", notify_mode: "immediate", recipients: "", notify_existing: false, is_asset: false, criticality: 3, org: "" };

/** Guess what the analyst pasted so the form starts on the right kind. */
function guessKind(value: string): string {
  const v = value.trim();
  if (/^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i.test(v)) return "email";
  if (/^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(v)) return "ip";
  if (/^cve-\d{4}-\d+$/i.test(v)) return "cve";
  if (/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(v)) return "hash";
  if (/^([a-z0-9-]+\.)+[a-z]{2,}$/i.test(v)) return "domain";
  return "keyword";
}

function WatchlistsPage() {
  const { canWrite, meta } = useSession();
  const params = useSearchParams();
  const router = useRouter();
  const { data, error, mutate } = useApi<Watch[]>("/watchlists");
  const { data: health } = useApi<{ email: { enabled: boolean; smtp_host: string; default_recipients: string[] } }>(canWrite ? "/system/health" : null);
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState(BLANK);
  const [editing, setEditing] = useState<Watch | null>(null);
  const { busy, run } = useAction();

  // "Watch" on the search page arrives here with the query pre-filled.
  useEffect(() => {
    const value = params.get("value");
    if (value && canWrite) {
      setForm({ ...BLANK, value, kind: guessKind(value) });
      setOpen(true);
      router.replace("/watchlists"); // so a reload does not reopen the dialog
    }
  }, [params, canWrite, router]);

  const set = (patch: Partial<typeof BLANK>) => setForm((f) => ({ ...f, ...patch }));
  const recipients = (text: string) => text.split(/[\s,;]+/).map((r) => r.trim()).filter(Boolean);
  const create = async () => {
    if (await run(() => api("/watchlists", { method: "POST", body: { ...form, recipients: recipients(form.recipients) } }), "Watching. Existing intelligence is being checked now.")) { setOpen(false); setForm(BLANK); mutate(); }
  };
  const save = async () => {
    if (!editing) return;
    const body = { name: editing.name, description: editing.description, min_severity: editing.min_severity, notify_mode: editing.notify_mode, recipients: editing.recipients, is_active: editing.is_active, is_asset: editing.is_asset, criticality: editing.criticality, org: editing.org };
    if (await run(() => api(`/watchlists/${editing.id}`, { method: "PATCH", body }), "Saved")) { setEditing(null); mutate(); }
  };
  const kind = WATCH_LABELS[form.kind];
  const defaults = health?.email.default_recipients ?? [];

  return (
    <>
      <PageHeader
        title="Watchlists"
        subtitle="Tell the platform what matters to you: your domains, people, brands, vendors and the technology you run. Every new finding is checked against these entries; a match raises an alert and, if you choose, an email. For conditions a single value cannot express, use a detection rule."
        actions={<><Link href="/rules"><Button>Detection rules</Button></Link>{canWrite && <Button variant="primary" onClick={() => { setForm(BLANK); setOpen(true); }}><Plus className="h-4 w-4" /> Add entry</Button>}</>}
      />
      {health && (
        <p className="mb-4 flex items-center gap-2 text-xs text-muted">
          <Mail className="h-3.5 w-3.5" />
          {health.email.enabled ? <>Alert email is on, sent through <span className="font-mono text-ink-2">{health.email.smtp_host}</span>. Default recipients: {defaults.length ? defaults.join(", ") : "none set"}.</> : "Alert email is switched off (EMAIL_ENABLED=false)."}
          <Link href="/settings" className="link">Email settings</Link>
        </p>
      )}
      <ErrorNote error={error} />
      {!data ? <Spinner /> : data.length === 0 ? (
        <Card><Empty title="Nothing is being watched yet" hint="Start with your organisation's domain: you will be alerted when it, a subdomain, or an employee mailbox appears in a leak, a ransomware post or a credential dump." action={canWrite && <Button variant="primary" onClick={() => setOpen(true)}><Plus className="h-4 w-4" /> Watch a domain</Button>} /></Card>
      ) : (
        <Card className="overflow-x-auto">
          <table className="w-full min-w-[760px]">
            <thead><tr className="border-b border-line"><th className="th">Watching</th><th className="th">Kind</th><th className="th">Email</th><th className="th text-right">Open alerts</th><th className="th text-right">Matches</th><th className="th">Last match</th><th className="th" /></tr></thead>
            <tbody className="divide-y divide-line">
              {data.map((w) => (
                <tr key={w.id} className={w.is_active ? "" : "opacity-60"}>
                  <td className="td"><div className="font-medium">{w.name}</div>{w.name !== w.value && <div className="break-all font-mono text-xs text-muted">{w.value}</div>}
                    <div className="mt-0.5 flex flex-wrap gap-1">{!w.is_active && <Badge>Paused</Badge>}{w.is_asset && <Badge tone="accent" title="An asset your organisation owns: look-alike detection is on and its criticality raises alert priority"><Building2 className="h-3 w-3" />Owned · {w.criticality}/5</Badge>}{w.org && <Badge>{w.org}</Badge>}</div></td>
                  <td className="td text-ink-2">{WATCH_LABELS[w.kind]?.label ?? w.kind}</td>
                  <td className="td text-xs text-ink-2">
                    {w.notify_mode === "none" ? <span className="inline-flex items-center gap-1 text-muted"><MailX className="h-3.5 w-3.5" />Off</span> : (
                      <><span className="inline-flex items-center gap-1"><Mail className="h-3.5 w-3.5" />{w.notify_mode === "digest" ? "Daily digest" : "Immediately"}</span>
                        <div className="text-muted">{w.recipients.length ? w.recipients.join(", ") : `default (${defaults.join(", ") || "none"})`}</div></>
                    )}
                    {w.min_severity !== "info" && <div className="text-muted">{titleCase(w.min_severity)} and above</div>}
                  </td>
                  <td className="td text-right tabular-nums">{w.open_alerts > 0 ? <Link className="link" href="/alerts">{w.open_alerts}</Link> : 0}</td>
                  <td className="td text-right tabular-nums">{w.match_count}</td>
                  <td className="td whitespace-nowrap text-xs text-muted">{ago(w.last_matched_at)}</td>
                  <td className="td">
                    {canWrite && (
                      <div className="flex justify-end gap-1">
                        <Button size="sm" onClick={() => setEditing(w)}>Edit</Button>
                        {w.is_asset && ["domain", "ip"].includes(w.kind) && <Link href="/attack-surface" title={w.last_scanned_at ? `Attack surface checked ${ago(w.last_scanned_at)}` : "Attack surface not checked yet"}><Button size="sm" variant="ghost"><Scan className="h-3.5 w-3.5" /></Button></Link>}
                        <Button size="sm" variant="ghost" title="Re-check everything already collected" onClick={() => run(() => api(`/watchlists/${w.id}/hunt`, { method: "POST" }), "Re-checking collected intelligence").then(() => setTimeout(() => mutate(), 4000))}><RefreshCw className="h-3.5 w-3.5" /></Button>
                        <Button size="sm" variant="ghost" title="Delete" onClick={() => confirm(`Stop watching "${w.name}"? Its alerts will be removed.`) && run(() => api(`/watchlists/${w.id}`, { method: "DELETE" }), "Deleted").then(() => mutate())}><Trash2 className="h-3.5 w-3.5" /></Button>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}

      <Modal open={open} onClose={() => setOpen(false)} title="Add a watchlist entry" footer={<><Button onClick={() => setOpen(false)}>Cancel</Button><Button variant="primary" busy={busy} disabled={form.value.trim().length < 2} onClick={create}>Start watching</Button></>}>
        <div className="space-y-4">
          <Field label="What to watch">
            <select className="field" value={form.kind} onChange={(e) => set({ kind: e.target.value })}>
              {meta.watch_kinds.map((k) => <option key={k} value={k}>{WATCH_LABELS[k]?.label ?? k}</option>)}
            </select>
          </Field>
          <Field label="Value" hint={kind?.hint}>
            <input className="field font-mono" value={form.value} placeholder={kind?.placeholder} onChange={(e) => set({ value: e.target.value })} />
          </Field>
          <Field label="Label (optional)"><input className="field" value={form.name} placeholder="e.g. Corporate domain" onChange={(e) => set({ name: e.target.value })} /></Field>
          {OWNABLE.includes(form.kind) && (
            <div className="rounded-md border border-line px-3 py-2.5">
              <label className="flex items-start gap-2 text-sm">
                <input type="checkbox" className="mt-0.5 accent-[var(--accent)]" checked={form.is_asset} onChange={(e) => set({ is_asset: e.target.checked })} />
                <span>This is an asset we own. <span className="text-muted">{form.kind === "domain" ? "Turns on look-alike domain detection and passive attack-surface discovery (certificate logs, public DNS and scan data; nothing is probed)." : form.kind === "ip" ? "Turns on passive attack-surface lookups for the range in public scan data. Nothing is probed." : "Raises the priority of alerts about it."}</span></span>
              </label>
              {form.is_asset && (
                <div className="mt-3 grid gap-4 sm:grid-cols-2">
                  <Field label="Business criticality" hint="How much it would hurt if this were compromised.">
                    <select className="field" value={form.criticality} onChange={(e) => set({ criticality: Number(e.target.value) })}>{[1, 2, 3, 4, 5].map((n) => <option key={n} value={n}>{CRITICALITY[n]}</option>)}</select>
                  </Field>
                  <Field label="Organisation or unit (optional)" hint="For subsidiaries and business units."><input className="field" value={form.org} placeholder="Retail banking" onChange={(e) => set({ org: e.target.value })} /></Field>
                </div>
              )}
            </div>
          )}
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Email alerts">
              <select className="field" value={form.notify_mode} onChange={(e) => set({ notify_mode: e.target.value })}>
                <option value="immediate">Immediately (within a minute)</option><option value="digest">Daily digest</option><option value="none">No email, console only</option>
              </select>
            </Field>
            <Field label="Alert on">
              <select className="field" value={form.min_severity} onChange={(e) => set({ min_severity: e.target.value })}>
                <option value="info">Every match</option><option value="medium">Medium and above</option><option value="high">High and above</option><option value="critical">Critical only</option>
              </select>
            </Field>
          </div>
          {form.notify_mode !== "none" && (
            <Field label="Send to" hint={`Comma separated. Leave empty to use the default recipients${defaults.length ? ` (${defaults.join(", ")})` : ""}.`}>
              <input className="field" value={form.recipients} placeholder="soc@example.co.ke, ciso@example.co.ke" onChange={(e) => set({ recipients: e.target.value })} />
            </Field>
          )}
          <label className="flex items-start gap-2 text-sm text-ink-2">
            <input type="checkbox" className="mt-0.5 accent-[var(--accent)]" checked={form.notify_existing} onChange={(e) => set({ notify_existing: e.target.checked })} />
            <span>Also email matches found in intelligence already collected. <span className="text-muted">Off by default: historic matches still appear in the alert queue, marked “Historic”.</span></span>
          </label>
        </div>
      </Modal>

      <Modal open={Boolean(editing)} onClose={() => setEditing(null)} title={`Edit: ${editing?.value ?? ""}`} footer={<><Button onClick={() => setEditing(null)}>Cancel</Button><Button variant="primary" busy={busy} onClick={save}>Save</Button></>}>
        {editing && (
          <div className="space-y-4">
            <Field label="Label"><input className="field" value={editing.name} onChange={(e) => setEditing({ ...editing, name: e.target.value })} /></Field>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Email alerts">
                <select className="field" value={editing.notify_mode} onChange={(e) => setEditing({ ...editing, notify_mode: e.target.value })}>
                  <option value="immediate">Immediately</option><option value="digest">Daily digest</option><option value="none">No email</option>
                </select>
              </Field>
              <Field label="Alert on">
                <select className="field" value={editing.min_severity} onChange={(e) => setEditing({ ...editing, min_severity: e.target.value })}>
                  <option value="info">Every match</option><option value="medium">Medium and above</option><option value="high">High and above</option><option value="critical">Critical only</option>
                </select>
              </Field>
            </div>
            <Field label="Send to" hint="Comma separated. Empty uses the default recipients.">
              <input className="field" value={editing.recipients.join(", ")} onChange={(e) => setEditing({ ...editing, recipients: recipients(e.target.value) })} />
            </Field>
            {OWNABLE.includes(editing.kind) && (
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label="Ownership">
                  <select className="field" value={editing.is_asset ? "yes" : "no"} onChange={(e) => setEditing({ ...editing, is_asset: e.target.value === "yes" })}><option value="no">Just watching</option><option value="yes">An asset we own</option></select>
                </Field>
                {editing.is_asset && <Field label="Business criticality"><select className="field" value={editing.criticality} onChange={(e) => setEditing({ ...editing, criticality: Number(e.target.value) })}>{[1, 2, 3, 4, 5].map((n) => <option key={n} value={n}>{CRITICALITY[n]}</option>)}</select></Field>}
                {editing.is_asset && <Field label="Organisation or unit"><input className="field" value={editing.org} onChange={(e) => setEditing({ ...editing, org: e.target.value })} /></Field>}
              </div>
            )}
            <label className="flex items-center gap-2 text-sm"><input type="checkbox" className="accent-[var(--accent)]" checked={editing.is_active} onChange={(e) => setEditing({ ...editing, is_active: e.target.checked })} /> Active</label>
          </div>
        )}
      </Modal>
    </>
  );
}

export default function Page() {
  return <Suspense fallback={<Spinner />}><WatchlistsPage /></Suspense>;
}

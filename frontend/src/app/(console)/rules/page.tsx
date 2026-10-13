"use client";

import { Mail, MailX, Play, Plus, Trash2 } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useState } from "react";
import { SeverityBadge } from "@/components/bits";
import { MiniColumns } from "@/components/charts";
import { PageHeader } from "@/components/shell";
import { useSession } from "@/components/session";
import { Badge, Button, Card, Empty, ErrorNote, Field, Modal, Spinner, useAction } from "@/components/ui";
import { api, useApi } from "@/lib/api";
import { ago, num } from "@/lib/format";

interface Rule {
  id: number; name: string; kind: string; query: string; threshold: number; window_hours: number; severity: string; notify_mode: string; recipients: string[];
  is_active: boolean; match_count: number; open_alerts: number; last_run_at: string | null; last_triggered_at: string | null; created_at: string;
}
interface Preview { current: number; previous_windows: number[]; baseline: number; interpretation: { kind: string; label: string; detail: string }[] }
const KINDS: Record<string, { label: string; hint: string }> = {
  query: { label: "Every new match", hint: "One alert for each new finding that matches the search." },
  threshold: { label: "Volume threshold", hint: "One alert when the number of matches in the window reaches the threshold." },
  spike: { label: "Unusual spike", hint: "One alert when matches in the window are well above the recent average." },
};
const WINDOWS = [[1, "1 hour"], [6, "6 hours"], [24, "24 hours"], [72, "3 days"], [168, "7 days"], [720, "30 days"]] as const;
const BLANK = { name: "", kind: "query", query: "", threshold: 5, window_hours: 24, severity: "medium", notify_mode: "immediate", recipients: "", is_active: true };

function describe(r: Pick<Rule, "kind" | "threshold" | "window_hours">) {
  const span = WINDOWS.find(([h]) => h === r.window_hours)?.[1] ?? `${r.window_hours} hours`;
  return r.kind === "query" ? "Alert on every new match" : r.kind === "threshold" ? `Alert at ${r.threshold}+ matches in ${span}` : `Alert on a spike (at least ${r.threshold} in ${span}, well above average)`;
}

function RulesPage() {
  const { canWrite } = useSession();
  const params = useSearchParams();
  const router = useRouter();
  const { data, error, mutate } = useApi<Rule[]>("/rules", { refreshInterval: 60000 });
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState(BLANK);
  const [editing, setEditing] = useState<number | null>(null);
  const [preview, setPreview] = useState<Preview | null>(null);
  const { busy, run } = useAction();
  const set = (patch: Partial<typeof BLANK>) => setForm((f) => ({ ...f, ...patch }));

  // "Alert on this search" on the search page arrives here with the query pre-filled.
  useEffect(() => {
    const query = params.get("query");
    if (query && canWrite) {
      setForm({ ...BLANK, query, name: query.slice(0, 80) });
      setEditing(null);
      setOpen(true);
      router.replace("/rules");
    }
  }, [params, canWrite, router]);

  // Show how the rule would have behaved before it is saved.
  useEffect(() => {
    if (!open || form.query.trim().length < 2) return setPreview(null);
    const timer = setTimeout(() => api<Preview>("/rules/preview", { method: "POST", body: { query: form.query, window_hours: form.window_hours } }).then(setPreview).catch(() => setPreview(null)), 400);
    return () => clearTimeout(timer);
  }, [open, form.query, form.window_hours]);

  const recipients = (text: string) => text.split(/[\s,;]+/).map((r) => r.trim()).filter(Boolean);
  const save = async () => {
    const body = { ...form, recipients: recipients(form.recipients) };
    const ok = await run(() => (editing ? api(`/rules/${editing}`, { method: "PATCH", body }) : api("/rules", { method: "POST", body })), editing ? "Rule saved" : "Rule created. It is evaluated every five minutes.");
    if (ok) { setOpen(false); mutate(); }
  };
  const edit = (r: Rule) => { setForm({ name: r.name, kind: r.kind, query: r.query, threshold: r.threshold, window_hours: r.window_hours, severity: r.severity, notify_mode: r.notify_mode, recipients: r.recipients.join(", "), is_active: r.is_active }); setEditing(r.id); setOpen(true); };

  return (
    <>
      <PageHeader
        title="Detection rules"
        subtitle="Turn any search into an alert. Watchlists cover single values such as a domain or an email; a rule covers anything the query language can express, and can alert on volume or on a sudden rise rather than on each match."
        actions={canWrite && <Button variant="primary" onClick={() => { setForm(BLANK); setEditing(null); setOpen(true); }}><Plus className="h-4 w-4" /> New rule</Button>}
      />
      <ErrorNote error={error} />
      {!data ? <Spinner /> : data.length === 0 ? (
        <Card><Empty title="No detection rules yet" hint={<>Examples: <code className="font-mono">type:ransomware sector:&quot;Financial services&quot; country:KE</code> on every match, or <code className="font-mono">type:phishing</code> as a spike rule to catch a campaign as it starts.</>} action={canWrite && <Button variant="primary" onClick={() => { setForm(BLANK); setEditing(null); setOpen(true); }}><Plus className="h-4 w-4" /> Create a rule</Button>} /></Card>
      ) : (
        <Card className="overflow-x-auto">
          <table className="w-full min-w-[820px]">
            <thead><tr className="border-b border-line"><th className="th">Rule</th><th className="th">Fires</th><th className="th">Email</th><th className="th text-right">Open alerts</th><th className="th text-right">Fired</th><th className="th">Last checked</th><th className="th" /></tr></thead>
            <tbody className="divide-y divide-line">
              {data.map((r) => (
                <tr key={r.id} className={r.is_active ? "" : "opacity-60"}>
                  <td className="td max-w-[22rem]"><div className="flex items-center gap-1.5 font-medium"><SeverityBadge severity={r.severity} /><span className="truncate">{r.name}</span>{!r.is_active && <Badge>Paused</Badge>}</div>
                    <Link href={`/search?q=${encodeURIComponent(r.query)}`} className="mt-0.5 block truncate font-mono text-xs text-muted hover:text-accent-ink" title="Run this search">{r.query}</Link></td>
                  <td className="td text-xs text-ink-2">{describe(r)}</td>
                  <td className="td text-xs text-ink-2">{r.notify_mode === "none" ? <span className="inline-flex items-center gap-1 text-muted"><MailX className="h-3.5 w-3.5" />Off</span> : <span className="inline-flex items-center gap-1"><Mail className="h-3.5 w-3.5" />{r.notify_mode === "digest" ? "Daily digest" : "Immediately"}</span>}</td>
                  <td className="td text-right tabular-nums">{r.open_alerts > 0 ? <Link className="link" href="/alerts">{r.open_alerts}</Link> : 0}</td>
                  <td className="td text-right tabular-nums">{num(r.match_count)}</td>
                  <td className="td whitespace-nowrap text-xs text-muted" title={r.last_triggered_at ? `Last fired ${ago(r.last_triggered_at)}` : "Never fired"}>{ago(r.last_run_at)}</td>
                  <td className="td">{canWrite && (
                    <div className="flex justify-end gap-1">
                      <Button size="sm" onClick={() => edit(r)}>Edit</Button>
                      <Button size="sm" variant="ghost" title="Evaluate now" onClick={() => run(() => api(`/rules/${r.id}/run`, { method: "POST" }), "Evaluating now").then(() => setTimeout(() => mutate(), 4000))}><Play className="h-3.5 w-3.5" /></Button>
                      <Button size="sm" variant="ghost" title="Delete" onClick={() => confirm(`Delete the rule "${r.name}"? Its alerts are kept.`) && run(() => api(`/rules/${r.id}`, { method: "DELETE" }), "Deleted").then(() => mutate())}><Trash2 className="h-3.5 w-3.5" /></Button>
                    </div>
                  )}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}

      <Modal open={open} onClose={() => setOpen(false)} wide title={editing ? "Edit rule" : "New detection rule"} footer={<><Button onClick={() => setOpen(false)}>Cancel</Button><Button variant="primary" busy={busy} disabled={form.name.trim().length < 3 || !form.query.trim()} onClick={save}>{editing ? "Save" : "Create rule"}</Button></>}>
        <div className="space-y-4">
          <Field label="Search to watch" hint="Anything the search box accepts: free text, indicators and operators.">
            <input className="field font-mono" value={form.query} placeholder='type:ransomware country:KE sector:"Financial services"' onChange={(e) => set({ query: e.target.value })} />
          </Field>
          {preview && (
            <div className="rounded-md border border-line bg-sunken px-3 py-2">
              <div className="flex flex-wrap items-center gap-1.5 text-xs">
                <span className="text-muted">Understood as</span>
                {preview.interpretation.length === 0 ? <span className="text-muted">everything</span> : preview.interpretation.map((i, n) => <Badge key={n} tone={i.kind === "warning" ? "warning" : i.kind === "exclude" ? "critical" : "accent"} title={i.detail || undefined}>{i.label}</Badge>)}
              </div>
              <div className="mt-2 grid items-end gap-3 sm:grid-cols-[auto_minmax(0,1fr)]">
                <p className="text-sm"><span className="text-lg font-semibold tabular-nums">{num(preview.current)}</span> match{preview.current === 1 ? "" : "es"} in the current window<span className="block text-xs text-muted">Average of the previous seven windows: {preview.baseline}</span></p>
                <MiniColumns values={[...preview.previous_windows].reverse().concat(preview.current)} labels={[...preview.previous_windows.map((_, i) => `${preview.previous_windows.length - i} windows ago`), "Current window"]} caption="Matches per window, oldest first" />
              </div>
            </div>
          )}
          <Field label="Name"><input className="field" value={form.name} placeholder="Ransomware against Kenyan banks" onChange={(e) => set({ name: e.target.value })} /></Field>
          <div className="grid gap-4 sm:grid-cols-3">
            <Field label="Fire when" hint={KINDS[form.kind]?.hint}>
              <select className="field" value={form.kind} disabled={Boolean(editing)} onChange={(e) => set({ kind: e.target.value })}>{Object.entries(KINDS).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}</select>
            </Field>
            <Field label="Window"><select className="field" value={form.window_hours} disabled={form.kind === "query"} onChange={(e) => set({ window_hours: Number(e.target.value) })}>{WINDOWS.map(([h, l]) => <option key={h} value={h}>{l}</option>)}</select></Field>
            <Field label={form.kind === "spike" ? "Minimum matches" : "Threshold"}><input className="field" type="number" min={1} disabled={form.kind === "query"} value={form.threshold} onChange={(e) => set({ threshold: Math.max(1, Number(e.target.value) || 1) })} /></Field>
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Alert severity"><select className="field" value={form.severity} onChange={(e) => set({ severity: e.target.value })}><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="info">Info</option></select></Field>
            <Field label="Email"><select className="field" value={form.notify_mode} onChange={(e) => set({ notify_mode: e.target.value })}><option value="immediate">Immediately</option><option value="digest">Daily digest</option><option value="none">No email, console only</option></select></Field>
          </div>
          {form.notify_mode !== "none" && <Field label="Send to" hint="Comma separated. Leave empty to use the default recipients."><input className="field" value={form.recipients} onChange={(e) => set({ recipients: e.target.value })} /></Field>}
          {editing && <label className="flex items-center gap-2 text-sm"><input type="checkbox" className="accent-[var(--accent)]" checked={form.is_active} onChange={(e) => set({ is_active: e.target.checked })} /> Active</label>}
        </div>
      </Modal>
    </>
  );
}

export default function Page() {
  return <Suspense fallback={<Spinner />}><RulesPage /></Suspense>;
}

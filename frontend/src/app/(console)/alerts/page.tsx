"use client";

import { Check, ChevronDown, Copy, Crosshair, KeyRound, Mail, MailX, Siren } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { Countries, FactorList, NetworkBadge, RiskMeter, SeverityBadge, VerificationBadge } from "@/components/bits";
import { PageHeader } from "@/components/shell";
import { useSession } from "@/components/session";
import { Badge, Button, Card, Empty, ErrorNote, Pagination, Spinner, Tabs, useAction } from "@/components/ui";
import { api, qs, useApi, type Factor } from "@/lib/api";
import { ago, cn, SEVERITY_ORDER, stamp, titleCase } from "@/lib/format";

interface Alert {
  id: number; category: string; reason: string; matched: string; snippet: string; severity: string; risk_score: number; status: string;
  created_at: string; notified_at: string | null; assigned_to: number | null; assignee: string; email_status: "off" | "pending" | "sent" | "not_sent";
  title: string; priority: number; factors: Factor[]; detail: Record<string, unknown>; origin: { type: "watchlist" | "rule" | "system"; id: number | null; name: string };
  // Rule alerts on volume have no single finding, and system alerts have no watchlist.
  watchlist: { id: number; name: string; kind: string; value: string; notify_mode: string; criticality: number; is_asset: boolean } | null;
  finding: { id: string; title: string; threat_type: string; network: string; source_name: string; countries: string[]; first_seen: string; has_credentials: boolean; verification: string; corroboration: number } | null;
}
const CATEGORY: Record<string, { label: string; tone: "critical" | "serious" | "warning" | "neutral" }> = {
  compromise: { label: "Possible compromise", tone: "critical" }, lookalike: { label: "Look-alike domain", tone: "serious" }, vulnerability: { label: "Vulnerability", tone: "serious" },
  attack_surface: { label: "Attack surface", tone: "serious" }, exposure: { label: "Identity exposure", tone: "critical" }, rule: { label: "Detection rule", tone: "neutral" },
  mention: { label: "Mention", tone: "neutral" },
};
interface AlertList { total: number; by_status: Record<string, number>; open_by_severity: Record<string, number>; open_by_category: Record<string, number>; items: Alert[] }

export default function AlertsPage() {
  const { me, canWrite, meta } = useSession();
  const [status, setStatus] = useState("open");
  const [severity, setSeverity] = useState("");
  const [category, setCategory] = useState("");
  const [mine, setMine] = useState(false);
  const [sort, setSort] = useState("priority");
  const [expanded, setExpanded] = useState<number | null>(null);
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const { data, error, mutate, isLoading } = useApi<AlertList>(`/alerts${qs({ status: status === "all" ? undefined : status, severity, category, mine, sort, page, size: 50 })}`, { refreshInterval: 60000, keepPreviousData: true });
  const { busy, run } = useAction();

  const act = async (ids: number[], next: string) => {
    const ok = await run(() => (ids.length === 1 ? api(`/alerts/${ids[0]}`, { method: "PATCH", body: { status: next } }) : api("/alerts/bulk", { method: "POST", body: { ids, status: next } })), `${ids.length} alert${ids.length === 1 ? "" : "s"} marked ${next.replace("_", " ")}`);
    if (ok) { setSelected(new Set()); mutate(); }
  };
  const assign = (id: number) => run(() => api(`/alerts/${id}`, { method: "PATCH", body: { assigned_to: me.id, status: "acknowledged" } }), "Assigned to you").then(() => mutate());
  const pick = (id: number) => setSelected((s) => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; });
  const reset = (fn: () => void) => { fn(); setPage(1); setSelected(new Set()); };
  const counts = data?.by_status ?? {};

  return (
    <>
      <PageHeader title="Alerts" subtitle="Matches from watchlists and detection rules, ordered by priority: how severe, how credible, how recent, and how much the affected asset matters to you. Open an alert to see what its priority is made of." actions={<><Link href="/rules"><Button>Detection rules</Button></Link><Link href="/watchlists"><Button>Manage watchlists</Button></Link></>} />

      {data && (
        <div className="mb-4 grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-6">
          <button onClick={() => reset(() => { setCategory(category === "compromise" ? "" : "compromise"); setStatus("open"); })} className={cn("card px-4 py-3 text-left", category === "compromise" && "border-critical")}>
            <div className="text-xs text-muted">Possible compromise</div><div className="mt-0.5 text-2xl font-semibold tabular-nums">{data.open_by_category.compromise ?? 0}</div>
          </button>
          {SEVERITY_ORDER.map((s) => (
            <button key={s} onClick={() => reset(() => { setSeverity(severity === s ? "" : s); setStatus("open"); })} className={cn("card px-4 py-3 text-left", severity === s && "border-accent")}>
              <SeverityBadge severity={s} /><div className="mt-1 text-2xl font-semibold tabular-nums">{data.open_by_severity[s] ?? 0}</div>
            </button>
          ))}
        </div>
      )}

      <Card>
        <div className="flex flex-wrap items-center gap-3 px-3 pt-1">
          <div className="min-w-0 flex-1">
            <Tabs value={status} onChange={(v) => reset(() => setStatus(v))} tabs={[
              { id: "open", label: "Open", count: counts.open ?? 0 }, { id: "acknowledged", label: "Acknowledged", count: counts.acknowledged ?? 0 },
              { id: "resolved", label: "Resolved", count: counts.resolved ?? 0 }, { id: "false_positive", label: "False positive", count: counts.false_positive ?? 0 }, { id: "all", label: "All" },
            ]} />
          </div>
          <select aria-label="Sort alerts" className="field mb-1 h-7 w-auto px-2 text-xs" value={sort} onChange={(e) => reset(() => setSort(e.target.value))}>
            <option value="priority">Highest priority</option><option value="newest">Newest</option>
          </select>
          <label className="flex items-center gap-1.5 pb-1 text-xs text-ink-2"><input type="checkbox" className="accent-[var(--accent)]" checked={mine} onChange={(e) => reset(() => setMine(e.target.checked))} /> Assigned to me</label>
        </div>

        {canWrite && selected.size > 0 && (
          <div className="flex flex-wrap items-center gap-2 border-b border-line bg-accent-soft px-4 py-2 text-sm">
            <span className="font-medium">{selected.size} selected</span>
            <Button size="sm" busy={busy} onClick={() => act([...selected], "acknowledged")}>Acknowledge</Button>
            <Button size="sm" busy={busy} onClick={() => act([...selected], "resolved")}>Resolve</Button>
            <Button size="sm" busy={busy} onClick={() => act([...selected], "false_positive")}>False positive</Button>
            <button className="link ml-auto text-xs" onClick={() => setSelected(new Set())}>Clear</button>
          </div>
        )}

        <ErrorNote error={error} />
        {!data && isLoading ? <Spinner /> : data && data.items.length === 0 ? (
          <Empty title={status === "open" ? "No open alerts" : "Nothing here"} hint="Alerts appear when something you watch shows up in collected intelligence. Watch a domain to catch leaked accounts, or a keyword to catch mentions." action={<Link href="/watchlists"><Button variant="primary">Add a watchlist entry</Button></Link>} />
        ) : (
          <ul className={cn("divide-y divide-line", isLoading && "opacity-60")}>
            {data?.items.map((a) => (
              <li key={a.id} className="px-4 py-3">
                <div className="flex gap-3">
                  {canWrite && <input type="checkbox" aria-label={`Select alert ${a.id}`} className="mt-1 h-3.5 w-3.5 shrink-0 accent-[var(--accent)]" checked={selected.has(a.id)} onChange={() => pick(a.id)} />}
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <SeverityBadge severity={a.severity} />
                      <Badge tone={CATEGORY[a.category]?.tone ?? "neutral"}>{a.category === "compromise" && <KeyRound className="h-3 w-3" />}{a.category === "lookalike" && <Copy className="h-3 w-3" />}{CATEGORY[a.category]?.label ?? titleCase(a.category)}</Badge>
                      {a.reason === "retro" && <Badge title="Found in intelligence collected before this watchlist entry existed">Historic</Badge>}
                      {a.status !== "open" && <Badge tone={a.status === "resolved" ? "good" : "neutral"}>{titleCase(a.status)}</Badge>}
                      <span className="break-all text-sm font-semibold">{a.matched}</span>
                    </div>
                    {a.finding ? <Link href={`/findings/${a.finding.id}`} className="mt-1 block truncate text-sm text-ink hover:underline">{a.finding.title}</Link>
                      : <p className="mt-1 truncate text-sm text-ink">{a.title}</p>}
                    {a.snippet && <p className="mt-1 line-clamp-2 break-words rounded bg-sunken px-2 py-1 font-mono text-xs text-ink-2">{a.snippet}</p>}
                    <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted">
                      <span className="inline-flex items-center gap-1">{a.origin.type === "rule" ? <Siren className="h-3 w-3" /> : <Crosshair className="h-3 w-3" />}{a.origin.type === "rule" ? "Rule" : a.origin.type === "watchlist" ? "Watchlist" : "Source"}: <span className="text-ink-2">{a.origin.name}</span></span>
                      {a.watchlist?.is_asset && <Badge title="An asset your organisation owns. Criticality raises the alert's priority.">Owned · criticality {a.watchlist.criticality}/5</Badge>}
                      {a.finding && <>
                        <span>{meta.threat_types[a.finding.threat_type] ?? a.finding.threat_type}</span>
                        <NetworkBadge network={a.finding.network} />
                        <span>{a.finding.source_name}</span>
                        <VerificationBadge state={a.finding.verification} corroboration={a.finding.corroboration} />
                        <Countries codes={a.finding.countries} />
                      </>}
                      <span title={stamp(a.created_at)}>{ago(a.created_at)}</span>
                      {a.email_status === "sent" ? <span className="inline-flex items-center gap-1"><Mail className="h-3 w-3" />Emailed</span>
                        : a.email_status === "pending" ? <span className="inline-flex items-center gap-1"><Mail className="h-3 w-3" />Email pending</span>
                        : <span className="inline-flex items-center gap-1" title={a.email_status === "off" ? "Email is off for this watchlist entry or rule" : "Historic match: not emailed"}><MailX className="h-3 w-3" />Not emailed</span>}
                      {a.assignee && <span>Assigned to {a.assignee}</span>}
                    </div>
                  </div>
                  <div className="flex shrink-0 flex-col items-end gap-1.5">
                    <button onClick={() => setExpanded(expanded === a.id ? null : a.id)} aria-expanded={expanded === a.id} title="Why this priority" className="inline-flex items-center gap-1 rounded px-1 py-0.5 text-xs text-muted hover:bg-sunken hover:text-ink">
                      <span className="hidden sm:inline">Priority</span><RiskMeter score={a.priority} /><ChevronDown className={cn("h-3 w-3 transition-transform", expanded === a.id && "rotate-180")} />
                    </button>
                    {canWrite && <>
                      {a.status === "open" && <Button size="sm" onClick={() => assign(a.id)}>Take</Button>}
                      {a.status !== "resolved" && <Button size="sm" onClick={() => act([a.id], "resolved")}><Check className="h-3.5 w-3.5" /> Resolve</Button>}
                      {a.status !== "open" && <Button size="sm" variant="ghost" onClick={() => act([a.id], "open")}>Reopen</Button>}
                    </>}
                  </div>
                </div>
                {expanded === a.id && (
                  <div className="mt-3 rounded-md border border-line bg-sunken">
                    <div className="border-b border-line px-4 py-2 text-xs font-semibold text-ink-2">Why this priority</div>
                    <FactorList factors={a.factors} total={a.priority} totalLabel="Priority" />
                    {a.origin.type === "rule" && <p className="border-t border-line px-4 py-2 text-xs text-muted">Raised by a detection rule. <Link className="link" href="/rules">Open detection rules</Link>{typeof a.detail.query === "string" && <> or <Link className="link" href={`/search?q=${encodeURIComponent(a.detail.query)}`}>run its search</Link></>}.</p>}
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
      </Card>
      {data && <Pagination page={page} size={50} total={data.total} onPage={setPage} />}
    </>
  );
}

"use client";

import { Ban, CheckCircle2, CircleHelp, Play, Plus, Radar, RefreshCw, ScrollText, XCircle } from "lucide-react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";
import { CrawlButton, Defanged, NetworkBadge } from "@/components/bits";
import { PageHeader } from "@/components/shell";
import { useSession } from "@/components/session";
import { Badge, Button, Card, Empty, ErrorNote, Field, Modal, Spinner, Tabs, useAction } from "@/components/ui";
import { api, qs, useApi } from "@/lib/api";
import { ago, stamp, titleCase } from "@/lib/format";

interface Source {
  id: number; name: string; url: string; host: string; network: string; connector: string; route: string; category: string; status: string;
  trust: number; crawl_interval_minutes: number; max_depth: number; max_pages: number; is_live: boolean | null; last_checked_at: string | null;
  last_live_at: string | null; last_crawled_at: string | null; last_http_status: number | null; last_error: string; consecutive_failures: number;
  doc_count: number; discovery_context: string; notes: string; egress_blocked: boolean;
  title: string; language: string; relevance: number; last_changed_at: string | null; created_at: string;
}
// The explorer's views: a status, or a way of looking across statuses.
const VIEWS = ["new", "changed", "referenced", "offline"] as const;
interface SourceList { counts: Record<string, number>; connector_labels?: Record<string, string>; views?: Record<string, number>; referenced?: Record<string, number>; onion?: { approved: number; candidate: number }; categories: string[]; connectors: Record<string, string>; egress_allow_hosts: string[]; items: Source[] }
interface LogRow { id: number; url: string; depth: number; probe: boolean; fetched_at: string; ok: boolean; http_status: number | null; bytes: number; elapsed_ms: number; error: string; new_docs: number; changed_docs: number; unchanged_docs: number }

const BLANK = { name: "", url: "", connector: "html", category: "other", route: "tor", trust: 50, crawl_interval_minutes: 360, max_depth: 1, max_pages: 25, notes: "", approve: false, feed_tag: "", render_js: false };

function Liveness({ s }: { s: Source }) {
  if (s.status === "blocked") return <Badge><Ban className="h-3 w-3" />Never contacted</Badge>;
  if (s.is_live === null) return <Badge><CircleHelp className="h-3 w-3" />Not checked yet</Badge>;
  return s.is_live
    ? <Badge tone="good" title={`Last answered ${stamp(s.last_live_at)}`}><CheckCircle2 className="h-3 w-3" />Live</Badge>
    : <Badge tone="critical" title={s.last_error}><XCircle className="h-3 w-3" />Unreachable</Badge>;
}

function SourcesPage() {
  const { canWrite, isAdmin } = useSession();
  const params = useSearchParams();
  const [status, setStatus] = useState(params.get("view") ?? "approved");
  const [q, setQ] = useState(params.get("q") ?? "");
  const [network, setNetwork] = useState("");
  const isView = (VIEWS as readonly string[]).includes(status);
  const { data, error, mutate } = useApi<SourceList>(`/sources${qs({ status: q || isView ? undefined : status, view: isView && !q ? status : undefined, q, network })}`, { refreshInterval: 30000, keepPreviousData: true });
  const [adding, setAdding] = useState(false);
  const [form, setForm] = useState(BLANK);
  const [logFor, setLogFor] = useState<Source | null>(null);
  const [group, setGroup] = useState("");
  const [discovering, setDiscovering] = useState(false);
  const { data: log } = useApi<LogRow[]>(logFor ? `/sources/${logFor.id}/log` : null);
  const { busy, run } = useAction();

  const set = (patch: Partial<typeof BLANK>) => setForm((f) => ({ ...f, ...patch }));
  const refresh = () => setTimeout(() => mutate(), 600);
  const patch = (s: Source, body: Record<string, unknown>, message: string) => run(() => api(`/sources/${s.id}`, { method: "PATCH", body }), message).then(refresh);
  const onion = /\.onion(\/|:|$)/i.test(form.url);
  const create = async () => {
    if (await run(() => api("/sources", { method: "POST", body: { ...form, route: onion ? "tor" : form.route } }), form.approve ? "Source added. First crawl queued." : "Source added as a candidate. Checking whether it is live.")) { setAdding(false); setForm(BLANK); refresh(); }
  };
  const discover = async () => {
    if (await run(() => api("/sources/discover", { method: "POST", body: { group: group || null } }), "Lookup queued. New sites appear under Candidates within a minute or two.")) { setDiscovering(false); setGroup(""); }
  };
  const counts = data?.counts ?? {};
  const torActive = data?.onion?.approved ?? 0;
  const torWaiting = data?.onion?.candidate ?? 0;
  // Candidates that answered their liveness check: the ones worth approving in one go.
  const responding = status === "candidate" ? (data?.items ?? []).filter((s) => s.status === "candidate" && s.is_live) : [];
  const approveResponding = () => confirm(`Approve ${responding.length} site${responding.length === 1 ? "" : "s"} that responded and start collecting from ${responding.length === 1 ? "it" : "them"}?\n\n${responding.map((s) => s.name).join("\n")}`)
    && run(async () => { for (const s of responding) await api(`/sources/${s.id}`, { method: "PATCH", body: { status: "approved" } }); }, `${responding.length} approved. First crawls are queued.`).then(refresh);

  return (
    <>
      <PageHeader
        title="Sources"
        subtitle="Every site the platform knows: what is being collected, what has been discovered and is waiting, what went offline and what changed. Onion sites are reached through the isolated Tor gateway. Open a source for its profile, history and connections."
        actions={canWrite && <>
          <Button onClick={() => setDiscovering(true)}><Radar className="h-4 w-4" /> Discover leak sites</Button>
          <CrawlButton label="Research crawl" size="md" />
          <Button variant="primary" onClick={() => setAdding(true)}><Plus className="h-4 w-4" /> Add source</Button>
        </>}
      />
      {data && torActive === 0 && (
        <div className="mb-4 flex flex-wrap items-center gap-x-3 gap-y-2 rounded-md border border-line bg-warning-soft px-3 py-2.5 text-sm">
          <span className="min-w-0 flex-1"><span className="font-semibold">Nothing is being collected from the dark web yet.</span> {torWaiting > 0
            ? <>{torWaiting} discovered onion site{torWaiting === 1 ? " is" : "s are"} waiting. The <Link className="link" href="/collection">collection policy</Link> decides which are collected automatically; you can approve any by hand.</>
            : <>No onion sites are on file. Use “Discover leak sites”, or add an onion address you already know.</>}</span>
          {torWaiting > 0 && status !== "candidate" && <Button size="sm" onClick={() => { setStatus("candidate"); setQ(""); }}>Review candidates</Button>}
        </div>
      )}
      <Card>
        <div className="flex flex-wrap items-center gap-3 px-3 pt-1">
          <div className="min-w-0 flex-1">
            <Tabs value={status} onChange={(v) => { setStatus(v); setQ(""); }} tabs={[
              { id: "approved", label: "Active", count: counts.approved ?? 0 }, { id: "candidate", label: "Discovered", count: counts.candidate ?? 0 },
              { id: "new", label: "New this week", count: data?.views?.new ?? 0 }, { id: "changed", label: "Recently changed", count: data?.views?.changed ?? 0 },
              { id: "referenced", label: "Most referenced", count: data?.views?.referenced ?? 0 }, { id: "offline", label: "Offline", count: data?.views?.offline ?? 0 },
              { id: "paused", label: "Paused", count: counts.paused ?? 0 }, { id: "blocked", label: "Blocked", count: counts.blocked ?? 0 },
            ]} />
          </div>
          {canWrite && responding.length > 0 && <Button size="sm" variant="primary" className="mb-1" busy={busy} onClick={approveResponding}>Approve all that respond ({responding.length})</Button>}
          <select aria-label="Network" className="field mb-1 h-8 w-auto px-2 text-xs" value={network} onChange={(e) => setNetwork(e.target.value)}><option value="">Tor and web</option><option value="onion">Tor only</option><option value="surface">Web only</option></select>
          <input className="field mb-1 h-8 w-52 text-xs" placeholder="Filter by name, title or address" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Filter sources" />
        </div>
        <ErrorNote error={error} />
        {!data ? <Spinner /> : data.items.length === 0 ? (
          <Empty title={status === "candidate" ? "No discovered sites waiting" : "No sources here"} hint={status === "candidate" ? "Sites appear here when a crawled page links to an onion service, when a victim tracker lists a group's leak site, or when a research crawl finds one." : undefined} />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[900px]">
              <thead><tr className="border-b border-line"><th className="th">Source</th><th className="th">Health</th><th className="th">Collection</th><th className="th text-right">Findings</th><th className="th">Last crawl</th><th className="th" /></tr></thead>
              <tbody className="divide-y divide-line">
                {data.items.map((s) => (
                  <tr key={s.id}>
                    <td className="td max-w-sm">
                      <div className="flex items-center gap-2"><Link href={`/sources/${s.id}`} className="truncate font-medium hover:text-accent-ink hover:underline">{s.title || s.name}</Link><NetworkBadge network={s.network} />
                        {s.relevance >= 4 && <Badge tone="accent" title={`Its own title scores ${s.relevance}/10 for security-research relevance`}>Relevant</Badge>}
                        {(data.referenced?.[s.id] ?? 0) > 0 && <Badge title="Other sources that link to it">{data.referenced![s.id]} link{data.referenced![s.id] === 1 ? "" : "s"} in</Badge>}</div>
                      {s.title && s.title !== s.name && <div className="truncate text-xs text-ink-2">{s.name}</div>}
                      <Defanged value={s.url} className="max-w-full text-muted" />
                      {s.discovery_context && <div className="mt-0.5 truncate text-xs text-muted">{s.discovery_context}</div>}
                      {isView && <div className="mt-0.5 text-2xs text-muted">{titleCase(s.status === "approved" ? "collecting" : s.status === "candidate" ? "discovered, not collected" : s.status)}{status === "new" ? ` · added ${ago(s.created_at)}` : status === "changed" ? ` · changed ${ago(s.last_changed_at)}` : ""}</div>}
                    </td>
                    <td className="td">
                      <Liveness s={s} />
                      {s.egress_blocked && <div className="mt-1 max-w-[15rem] text-xs text-warning">Host is not in EGRESS_ALLOW_HOSTS. Add it, or switch the route to Tor.</div>}
                      {s.last_error && s.status !== "blocked" && <div className="mt-1 line-clamp-2 max-w-[15rem] break-words text-xs text-muted" title={s.last_error}>{s.last_error}</div>}
                      {s.last_checked_at && <div className="mt-0.5 text-2xs text-muted">Checked {ago(s.last_checked_at)}</div>}
                    </td>
                    <td className="td text-xs text-ink-2">
                      <div>{data.connector_labels?.[s.connector] ?? data.connectors[s.connector] ?? s.connector} · {titleCase(s.category)}</div>
                      <div className="text-muted">via {s.route === "tor" ? "Tor" : "allowlisted proxy"} · every {s.crawl_interval_minutes >= 60 ? `${Math.round(s.crawl_interval_minutes / 60)} h` : `${s.crawl_interval_minutes} min`} · trust {s.trust}</div>
                    </td>
                    <td className="td text-right tabular-nums">{s.doc_count}</td>
                    <td className="td whitespace-nowrap text-xs text-muted">{ago(s.last_crawled_at)}</td>
                    <td className="td">
                      <div className="flex justify-end gap-1">
                        <Link href={`/sources/${s.id}`}><Button size="sm">Profile</Button></Link>
                        <Button size="sm" variant="ghost" title="Crawl log" onClick={() => setLogFor(s)}><ScrollText className="h-3.5 w-3.5" /></Button>
                        {canWrite && s.status !== "blocked" && <Button size="sm" variant="ghost" title="Verify the link is alive" onClick={() => run(() => api(`/sources/${s.id}/verify`, { method: "POST" }), "Liveness check queued").then(() => setTimeout(() => mutate(), 8000))}><RefreshCw className="h-3.5 w-3.5" /></Button>}
                        {canWrite && s.status === "approved" && <Button size="sm" title="Crawl now" onClick={() => run(() => api(`/sources/${s.id}/crawl`, { method: "POST" }), "Crawl queued").then(() => setTimeout(() => mutate(), 8000))}><Play className="h-3.5 w-3.5" /> Crawl</Button>}
                        {canWrite && s.status === "approved" && <Button size="sm" onClick={() => patch(s, { status: "paused" }, "Paused")}>Pause</Button>}
                        {canWrite && (s.status === "candidate" || s.status === "paused") && <Button size="sm" variant="primary" onClick={() => patch(s, { status: "approved" }, "Approved. First crawl starts within a minute.")}>Approve</Button>}
                        {canWrite && s.status !== "blocked" && <Button size="sm" variant="danger" title="Never contact this site again" onClick={() => confirm(`Block ${s.name}? It will never be contacted again.`) && patch(s, { status: "blocked" }, "Blocked")}>Block</Button>}
                        {isAdmin && s.status === "blocked" && <Button size="sm" onClick={() => patch(s, { status: "candidate" }, "Unblocked, back to candidates")}>Unblock</Button>}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      {data && <p className="mt-3 text-xs text-muted">Direct clearnet egress is limited to: <span className="font-mono">{data.egress_allow_hosts.join(", ") || "nothing"}</span>. Everything else must use the Tor route.</p>}

      <Modal open={adding} onClose={() => setAdding(false)} title="Add a source" footer={<><Button onClick={() => setAdding(false)}>Cancel</Button><Button variant="primary" busy={busy} disabled={!form.name.trim() || form.url.trim().length < 8} onClick={create}>Add source</Button></>}>
        <div className="space-y-4">
          <Field label="Name"><input className="field" value={form.name} onChange={(e) => set({ name: e.target.value })} placeholder="e.g. Example leak blog" /></Field>
          <Field label="URL" hint="A publicly readable page, feed or API. Pages behind a login or CAPTCHA are reported as such and are not collected.">
            <input className="field font-mono" value={form.url} onChange={(e) => set({ url: e.target.value })} placeholder="http://…onion/ or https://…" spellCheck={false} />
          </Field>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Type"><select className="field" value={form.connector} onChange={(e) => set({ connector: e.target.value })}>{Object.entries(data?.connectors ?? {}).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></Field>
            <Field label="Category"><select className="field" value={form.category} onChange={(e) => set({ category: e.target.value })}>{(data?.categories ?? []).map((c) => <option key={c} value={c}>{titleCase(c)}</option>)}</select></Field>
            <Field label="Route" hint={onion ? "Onion sites always use Tor." : "Direct works only for hosts in EGRESS_ALLOW_HOSTS."}>
              <select className="field" disabled={onion} value={onion ? "tor" : form.route} onChange={(e) => set({ route: e.target.value })}><option value="tor">Through Tor</option><option value="direct">Direct (allowlisted HTTPS)</option></select>
            </Field>
            <Field label="Crawl every"><select className="field" value={form.crawl_interval_minutes} onChange={(e) => set({ crawl_interval_minutes: Number(e.target.value) })}>
              <option value={60}>Hour</option><option value={180}>3 hours</option><option value={360}>6 hours</option><option value={720}>12 hours</option><option value={1440}>Day</option></select></Field>
            <Field label="Reliability (0-100)" hint="How much you trust this source; feeds the risk score."><input type="number" min={0} max={100} className="field" value={form.trust} onChange={(e) => set({ trust: Number(e.target.value) })} /></Field>
            {form.connector === "ioc_feed" && <Field label="What the feed lists" hint="A short tag put on every indicator, e.g. phishing, c2, botnet."><input className="field font-mono" value={form.feed_tag} placeholder="c2" onChange={(e) => set({ feed_tag: e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, "") })} /></Field>}
            {form.connector === "html" && <Field label="Pages per crawl" hint="Follows links on the same site, one level deep."><input type="number" min={1} max={200} className="field" value={form.max_pages} onChange={(e) => set({ max_pages: Number(e.target.value) })} /></Field>}
          </div>
          {form.connector === "telegram_public" && <p className="rounded-md bg-sunken px-3 py-2 text-xs text-muted">Reads the public web preview of a channel (t.me/s/…), the same page anyone can open without an account. Private channels, groups and anything that needs joining or logging in are out of scope. Add <code className="font-mono">t.me</code> to EGRESS_ALLOW_HOSTS for the direct route.</p>}
          {form.connector === "ioc_feed" && <p className="rounded-md bg-sunken px-3 py-2 text-xs text-muted">A plain-text list with one indicator per line. Listed indicators are recorded and flagged wherever they appear in findings or on your attack surface. They are never contacted.</p>}
          {form.connector === "html" && <label className="flex items-start gap-2 text-sm text-ink-2"><input type="checkbox" className="mt-0.5 accent-[var(--accent)]" checked={form.render_js} onChange={(e) => set({ render_js: e.target.checked })} /><span>Render JavaScript. <span className="text-muted">For sites that are empty without scripts. Each page loads in a disposable, network-isolated browser through the same route; slower, and images are never loaded.</span></span></label>}
          <label className="flex items-start gap-2 text-sm text-ink-2"><input type="checkbox" className="mt-0.5 accent-[var(--accent)]" checked={form.approve} onChange={(e) => set({ approve: e.target.checked })} /><span>Approve and start collecting now. <span className="text-muted">Otherwise it is added as a candidate and only checked for liveness.</span></span></label>
        </div>
      </Modal>

      <Modal open={discovering} onClose={() => setDiscovering(false)} title="Discover ransomware leak sites" footer={<><Button onClick={() => setDiscovering(false)}>Cancel</Button><Button variant="primary" busy={busy} onClick={discover}>Look up</Button></>}>
        <p className="mb-3 text-sm text-ink-2">Looks up where a ransomware group publishes, using the public RansomLook tracker, and files each site as a candidate. Sites behind a CAPTCHA, file servers and chat panels are skipped. Nothing is crawled until you approve it.</p>
        <Field label="Group name" hint="As the tracker spells it, e.g. akira, qilin, lockbit3. Leave empty to look up the groups most active in your recent findings."><input className="field font-mono" value={group} onChange={(e) => setGroup(e.target.value)} placeholder="akira" /></Field>
      </Modal>

      <Modal open={Boolean(logFor)} onClose={() => setLogFor(null)} title={`Crawl log: ${logFor?.name ?? ""}`} wide>
        {!log ? <Spinner /> : log.length === 0 ? <p className="text-sm text-muted">No fetches recorded yet.</p> : (
          <div className="scroll-thin max-h-[60vh] overflow-auto">
            <table className="w-full text-xs">
              <thead><tr className="border-b border-line"><th className="th">When</th><th className="th">Result</th><th className="th">Page</th><th className="th text-right">Size</th><th className="th text-right">Time</th><th className="th">Findings</th></tr></thead>
              <tbody className="divide-y divide-line">
                {log.map((r) => (
                  <tr key={r.id}>
                    <td className="td whitespace-nowrap text-xs text-muted" title={stamp(r.fetched_at)}>{ago(r.fetched_at)}</td>
                    <td className="td text-xs">{r.ok ? <Badge tone="good">{r.http_status}</Badge> : <Badge tone="critical">{r.http_status ?? "failed"}</Badge>}{r.probe && <span className="ml-1 text-muted">liveness</span>}{r.error && <div className="mt-0.5 max-w-xs break-words text-muted">{r.error}</div>}</td>
                    <td className="td max-w-[14rem] text-xs"><span className="block truncate font-mono text-muted" title={r.url}>{r.url.replace(/^https?:\/\/[^/]+/, "") || "/"}</span></td>
                    <td className="td whitespace-nowrap text-right text-xs tabular-nums">{r.bytes ? `${Math.round(r.bytes / 1024)} KB` : ""}</td>
                    <td className="td whitespace-nowrap text-right text-xs tabular-nums">{(r.elapsed_ms / 1000).toFixed(1)} s</td>
                    <td className="td whitespace-nowrap text-xs">{r.probe ? "" : `${r.new_docs} new · ${r.changed_docs} changed · ${r.unchanged_docs} same`}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Modal>
    </>
  );
}

export default function Page() {
  return <Suspense fallback={<Spinner />}><SourcesPage /></Suspense>;
}

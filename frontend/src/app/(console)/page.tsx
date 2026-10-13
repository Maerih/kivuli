"use client";

import { Activity, ArrowRight, Bookmark, Crosshair, Radar, Search } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, type FormEvent, type ReactNode } from "react";
import { CrawlButton, FindingRow, SeverityBadge, StateBadge } from "@/components/bits";
import { useSession } from "@/components/session";
import { Badge, Button, Card, CardHeader, ErrorNote, Spinner } from "@/components/ui";
import { useApi, type CollectionStatus, type CrawlJob, type FindingSummary, type SourceBrief } from "@/lib/api";
import { ago, cn, compact, defang, num, shortHost, SOURCE_KIND_LABELS, WATCH_LABELS } from "@/lib/format";

interface Home {
  collection: CollectionStatus;
  recent_onion: FindingSummary[]; recent: FindingSummary[]; critical: FindingSummary[]; new_sources: SourceBrief[];
  matches: { id: number; severity: string; category: string; matched: string; created_at: string; priority: number; title: string; finding_id: string | null }[];
  watched: { id: number; name: string; kind: string; value: string; open_alerts: number; match_count: number; last_matched_at: string | null }[];
  investigations: { id: number; title: string; status: string; priority: string; updated_at: string; items: number }[];
  crawls: CrawlJob[];
}
const EXAMPLES = ["cyber attack kenya", "leaked credentials", "ransomware kenya", "company.com", "username@example.com", '"initial access" bank', "kind:leak lang:russian"];

function Panel({ title, hint, href, more, children }: { title: string; hint?: string; href?: string; more?: string; children: ReactNode }) {
  return (
    <Card className="flex min-w-0 flex-col">
      <CardHeader title={title} hint={hint} action={href && <Link href={href} className="link inline-flex items-center gap-0.5 text-xs">{more ?? "All"} <ArrowRight className="h-3 w-3" /></Link>} />
      <div className="min-w-0 flex-1">{children}</div>
    </Card>
  );
}
const Nothing = ({ children }: { children: ReactNode }) => <p className="px-4 py-6 text-center text-sm text-muted">{children}</p>;

function Status({ label, value, sub, bad, href = "/collection" }: { label: string; value: string; sub?: string; bad?: boolean; href?: string }) {
  return (
    <Link href={href} className="block min-w-0 rounded-md border border-line bg-raised px-3 py-2 hover:border-line-strong">
      <div className="label truncate">{label}</div>
      <div className={cn("mt-0.5 truncate text-base font-semibold tabular-nums", bad && "text-critical")}>{value}</div>
      {sub && <div className="truncate text-2xs text-muted">{sub}</div>}
    </Link>
  );
}

export default function CommandCentre() {
  const router = useRouter();
  const { canWrite } = useSession();
  const { data, error } = useApi<Home>("/research/home", { refreshInterval: 30000 });
  const { data: saved } = useApi<{ id: number; name: string; query: string; params: Record<string, string> }[]>("/saved-searches");
  const [q, setQ] = useState("");
  const [darkOnly, setDarkOnly] = useState(false);
  const go = (query: string) => router.push(`/search?q=${encodeURIComponent(query)}${darkOnly ? "&network=onion" : ""}`);
  const submit = (e: FormEvent) => { e.preventDefault(); if (q.trim()) go(q.trim()); };
  const c = data?.collection;
  const dark = data?.recent_onion ?? [];

  return (
    <>
      <section className="mx-auto mb-6 max-w-4xl pt-2">
        <form onSubmit={submit} role="search" className="relative">
          <Search className="pointer-events-none absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-muted" />
          <input value={q} onChange={(e) => setQ(e.target.value)} autoFocus spellCheck={false} aria-label="Search dark-web intelligence"
            placeholder="Search dark-web intelligence: a keyword, domain, email, person, organisation, indicator or actor"
            className="h-14 w-full rounded-xl border border-line-strong bg-raised pl-12 pr-28 text-base shadow-pop placeholder:text-muted" />
          <Button variant="primary" type="submit" className="absolute right-2 top-1/2 h-10 -translate-y-1/2 px-5">Search</Button>
        </form>
        <div className="mt-2.5 flex flex-wrap items-center gap-x-2 gap-y-1.5 text-xs">
          <label className="mr-1 flex cursor-pointer items-center gap-1.5 text-ink-2"><input type="checkbox" className="accent-[var(--accent)]" checked={darkOnly} onChange={(e) => setDarkOnly(e.target.checked)} /> Tor sources only</label>
          {EXAMPLES.map((ex) => <button key={ex} onClick={() => go(ex)} className="rounded border border-line px-1.5 py-0.5 font-mono text-ink-2 hover:border-accent hover:text-accent-ink">{ex}</button>)}
          {(saved ?? []).slice(0, 4).map((s) => <Link key={s.id} href={`/search?${s.params?.qs ?? `q=${encodeURIComponent(s.query)}`}`} className="inline-flex items-center gap-1 rounded border border-line px-1.5 py-0.5 text-ink-2 hover:border-accent hover:text-accent-ink"><Bookmark className="h-3 w-3" />{s.name}</Link>)}
        </div>
      </section>

      <ErrorNote error={error} />
      {!data || !c ? <Spinner /> : (
        <>
          <section aria-label="Collection status" className="mb-4 grid grid-cols-2 gap-2 sm:grid-cols-4 xl:grid-cols-8">
            <Status label="Tor connection" value={c.tor.online ? "Online" : "Offline"} sub={c.tor.online ? `exit ${c.tor.exit_ip}` : c.tor.error || "not ready"} bad={!c.tor.online} />
            <Status label="Collectors" value={`${c.collectors.online}/${c.collectors.expected}`} sub="worker roles answering" bad={c.collectors.online < c.collectors.expected} />
            <Status label="Active sources" value={num(c.sources.active)} sub={`${num(c.sources.active_onion)} on Tor`} href="/sources" />
            <Status label="Offline sources" value={num(c.sources.offline)} sub={`${num(c.sources.candidates_onion)} onion candidates`} href="/sources" />
            <Status label="Crawl queue" value={num(c.queue.crawl + c.queue.pipeline)} sub={`${c.crawls_running} research crawl${c.crawls_running === 1 ? "" : "s"} running`} />
            <Status label="Pages indexed" value={compact(c.pages.indexed)} sub={`${compact(c.pages.onion)} from Tor · ${num(c.pages.new_24h)} new today`} href="/search" />
            <Status label="Last collection" value={c.last_collection ? ago(c.last_collection) : "never"} sub={`${num(c.fetches_24h)} fetches in 24 h`} />
            <Status label="Failed fetches" value={num(c.failed_24h)} sub="last 24 hours" bad={c.fetches_24h > 20 && c.failed_24h > c.fetches_24h / 2} />
          </section>

          {c.sources.active_onion === 0 && (
            <div className="mb-4 flex flex-wrap items-center gap-x-3 gap-y-2 rounded-md border border-line bg-warning-soft px-3 py-2.5 text-sm">
              <Radar className="h-4 w-4 shrink-0 text-warning" />
              <span className="min-w-0 flex-1"><span className="font-semibold">Nothing is being collected from Tor yet.</span> {c.sources.candidates_onion > 0 ? `${c.sources.candidates_onion} discovered onion site${c.sources.candidates_onion === 1 ? " is" : "s are"} waiting.` : "Discover leak sites, or start a research crawl from an onion address."}</span>
              <Link href="/sources"><Button size="sm">Open the source explorer</Button></Link>
              <CrawlButton label="Research crawl" />
            </div>
          )}

          <div className="grid gap-4 xl:grid-cols-3">
            <div className="min-w-0 space-y-4 xl:col-span-2">
              <Panel title="Recent intelligence" hint={dark.length ? "Newest findings collected through Tor" : "Newest findings (nothing from Tor yet)"} href={dark.length ? "/search?network=onion&sort=newest" : "/search?sort=newest"} more="Search all">
                {(dark.length ? dark : data.recent).length === 0 ? <Nothing>Nothing collected yet. The first crawl starts within a minute of the stack coming up.</Nothing> : (dark.length ? dark : data.recent).map((f) => <FindingRow key={f.id} f={f} />)}
              </Panel>
              <Panel title="Critical findings" hint="Highest risk in the last seven days" href="/search?sort=risk&min_risk=70" more="All high risk">
                {data.critical.length === 0 ? <Nothing>No high-risk findings this week.</Nothing> : data.critical.map((f) => <FindingRow key={f.id} f={f} />)}
              </Panel>
            </div>

            <div className="min-w-0 space-y-4">
              <Panel title="New matches" hint="Open alerts on what you watch" href="/alerts" more="Queue">
                {data.matches.length === 0 ? <Nothing>No open matches. <Link className="link" href="/watchlists">Watch a keyword or domain</Link>.</Nothing> : (
                  <ul className="divide-y divide-line">
                    {data.matches.map((a) => (
                      <li key={a.id} className="px-4 py-2">
                        <div className="flex items-center gap-2"><SeverityBadge severity={a.severity} /><span className="min-w-0 truncate text-sm font-medium">{a.matched}</span></div>
                        <Link href={a.finding_id ? `/findings/${a.finding_id}` : "/alerts"} className="mt-0.5 line-clamp-1 text-xs text-ink-2 hover:underline">{a.title}</Link>
                        <div className="text-2xs text-muted">{ago(a.created_at)}</div>
                      </li>
                    ))}
                  </ul>
                )}
              </Panel>
              <Panel title="Watched keywords" href="/watchlists" more="Manage">
                {data.watched.length === 0 ? <Nothing>Nothing is being watched. <Link className="link" href="/watchlists">Add a keyword, domain or email</Link>.</Nothing> : (
                  <ul className="divide-y divide-line">
                    {data.watched.map((w) => (
                      <li key={w.id} className="flex items-center gap-2 px-4 py-2 text-sm">
                        <Crosshair className="h-3.5 w-3.5 shrink-0 text-muted" />
                        <Link href={`/search?q=${encodeURIComponent(w.value)}`} className="min-w-0 flex-1 truncate hover:underline" title={`Search for ${w.value}`}>{w.value}</Link>
                        <span className="shrink-0 text-2xs text-muted">{WATCH_LABELS[w.kind]?.label ?? w.kind}</span>
                        {w.open_alerts > 0 ? <Badge tone="critical">{w.open_alerts} open</Badge> : <span className="shrink-0 text-2xs text-muted">{w.match_count} matches</span>}
                      </li>
                    ))}
                  </ul>
                )}
              </Panel>
              <Panel title="New sources" hint="Discovered or added in the last seven days" href="/sources?view=new" more="Explorer">
                {data.new_sources.length === 0 ? <Nothing>No new sources this week.</Nothing> : (
                  <ul className="divide-y divide-line">
                    {data.new_sources.map((s) => (
                      <li key={s.id} className="px-4 py-2">
                        <div className="flex items-center gap-2"><Link href={`/sources/${s.id}`} className="min-w-0 flex-1 truncate text-sm font-medium hover:underline">{s.title || s.name}</Link><StateBadge state={s.state} /></div>
                        <div className="truncate text-2xs text-muted"><span className="font-mono">{defang(shortHost(s.host))}</span> · {SOURCE_KIND_LABELS[s.category] ?? s.category} · {s.status === "approved" ? "collecting" : s.status} · {ago(s.created_at)}</div>
                      </li>
                    ))}
                  </ul>
                )}
              </Panel>
              <Panel title="Active research" hint="Open investigations and research crawls" href="/cases" more="Investigations">
                {data.investigations.length + data.crawls.length === 0 ? <Nothing>No open investigations or crawls.</Nothing> : (
                  <ul className="divide-y divide-line">
                    {data.crawls.filter((j) => j.status === "running").map((j) => (
                      <li key={`j${j.id}`} className="flex items-center gap-2 px-4 py-2 text-sm">
                        <Activity className="h-3.5 w-3.5 shrink-0 animate-pulse text-accent-ink" />
                        <Link href={`/crawls/${j.id}`} className="min-w-0 flex-1 truncate font-mono text-xs hover:underline">{defang(shortHost(j.source.host))}</Link>
                        <span className="shrink-0 text-2xs text-muted">{j.progress.fetched} pages · depth {j.depth}</span>
                      </li>
                    ))}
                    {data.investigations.map((i) => (
                      <li key={`c${i.id}`} className="flex items-center gap-2 px-4 py-2 text-sm">
                        <Link href={`/cases/${i.id}`} className="min-w-0 flex-1 truncate hover:underline">{i.title}</Link>
                        <span className="shrink-0 text-2xs text-muted">{i.items} items · {ago(i.updated_at)}</span>
                      </li>
                    ))}
                  </ul>
                )}
                {canWrite && <div className="flex gap-2 border-t border-line px-4 py-2"><CrawlButton label="Research crawl" /><Link href="/cases"><Button size="sm">New investigation</Button></Link></div>}
              </Panel>
            </div>
          </div>
        </>
      )}
    </>
  );
}

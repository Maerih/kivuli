"use client";

import { ArrowLeft, ArrowRight, Play, RefreshCw } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useState } from "react";
import { CrawlButton, Defanged, FindingRow, NetworkBadge, Notes, StateBadge } from "@/components/bits";
import { BarList } from "@/components/charts";
import { PageHeader } from "@/components/shell";
import { useSession } from "@/components/session";
import { Badge, Button, Card, CardHeader, Empty, ErrorNote, Spinner, Tabs, useAction } from "@/components/ui";
import { api, useApi, type CrawlJob, type FindingSummary, type SourceBrief } from "@/lib/api";
import { ago, cn, day, defang, ENTITY_LABELS, shortHost, SOURCE_KIND_LABELS, stamp } from "@/lib/format";

interface Profile extends SourceBrief {
  url: string; route: string; connector: string; trust: number; language: string; language_name: string; notes: string; crawl_interval_minutes: number;
  max_depth: number; max_pages: number; render_js: boolean; last_error: string; last_checked_at: string | null; last_crawled_at: string | null; last_changed_at: string | null;
  defanged: string; discovered_from: { id: number; name: string } | null;
  observed: { first: string | null; last: string | null; pages: number };
  availability: { checks_30d: number; answered_30d: number; percent: number | null; days: { date: string; checks: number; answered: number }[] };
  pages: (FindingSummary & { missing: boolean })[];
  links_out: { host: string; count: number; last_seen: string; source: SourceBrief | null }[];
  links_in: { count: number; last_seen: string; source: SourceBrief }[];
  entities: { id: number; type: string; name: string; count: number }[];
  crawls: CrawlJob[];
  runs: { run_id: string; at: string; fetched: number; ok: number; new: number; changed: number }[];
}

export default function SourceProfilePage() {
  const { id } = useParams<{ id: string }>();
  const { canWrite } = useSession();
  const { data: s, error, mutate } = useApi<Profile>(`/sources/${id}/profile`, { refreshInterval: 30000 });
  const [tab, setTab] = useState<"pages" | "related" | "history" | "notes">("pages");
  const { busy, run } = useAction();
  const back = <Link href="/sources" className="mb-3 inline-flex items-center gap-1 text-xs text-muted hover:text-ink"><ArrowLeft className="h-3.5 w-3.5" /> Source explorer</Link>;
  if (error) return <>{back}<ErrorNote error={error} /></>;
  if (!s) return <Spinner />;
  const patch = (body: Record<string, unknown>, message: string) => run(() => api(`/sources/${s.id}`, { method: "PATCH", body }), message).then(() => mutate());
  const act = (path: string, message: string) => run(() => api(`/sources/${s.id}/${path}`, { method: "POST" }), message).then(() => setTimeout(() => mutate(), 6000));
  const site = s.connector === "html";
  const fact = (label: string, value: React.ReactNode) => <div><dt className="label">{label}</dt><dd className="mt-0.5 text-sm">{value}</dd></div>;
  const actors = s.entities.filter((e) => e.type === "actor" || e.type === "malware");
  const others = s.entities.filter((e) => e.type !== "actor" && e.type !== "malware" && e.type !== "technique");

  return (
    <>
      {back}
      <PageHeader
        title={s.title || s.name}
        subtitle={<span className="flex flex-wrap items-center gap-1.5 pt-1">
          <StateBadge state={s.state} /><NetworkBadge network={s.network} /><Badge tone="accent">{SOURCE_KIND_LABELS[s.category] ?? s.category}</Badge>
          <Badge tone={s.status === "approved" ? "good" : s.status === "blocked" ? "critical" : "neutral"}>{s.status === "approved" ? "Being collected" : s.status === "candidate" ? "Discovered, not collected" : s.status === "paused" ? "Not monitored" : "Blocked"}</Badge>
          {s.relevance >= 4 && <Badge tone="accent" title="Scored from the site's own title">Relevance {s.relevance}/10</Badge>}
          {s.title && s.title !== s.name && <span className="text-xs">{s.name}</span>}
        </span>}
        actions={<>
          <Link href={`/search?q=${encodeURIComponent(`site:${s.host}`)}`}><Button>Search this source</Button></Link>
          {canWrite && s.status !== "blocked" && <>
            {site && <CrawlButton url={s.url} label="Research crawl" size="md" />}
            {s.status === "approved" && <Button busy={busy} onClick={() => act("crawl", "Crawl queued")}><Play className="h-3.5 w-3.5" /> Crawl now</Button>}
            <Button busy={busy} title="Check that the site answers" onClick={() => act("verify", "Checking whether it answers")}><RefreshCw className="h-3.5 w-3.5" /> Check</Button>
            {s.status === "approved" ? <Button onClick={() => patch({ status: "paused" }, "No longer monitored")}>Stop monitoring</Button>
              : <Button variant="primary" onClick={() => patch({ status: "approved" }, "Monitoring. First crawl starts within a minute.")}>Monitor</Button>}
          </>}
        </>}
      />

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_22rem]">
        <div className="min-w-0 space-y-4">
          <Card>
            <dl className="grid gap-4 px-4 py-3 sm:grid-cols-2 lg:grid-cols-4">
              {fact(s.network === "onion" ? "Onion address" : "Address", <Defanged value={s.url} pivot />)}
              {fact("First observed", <>{day(s.observed.first) || "never"}<span className="block text-xs text-muted">{s.discovered_from ? <>found via <Link className="link" href={`/sources/${s.discovered_from.id}`}>{s.discovered_from.name}</Link></> : s.discovery_context || "added by hand"}</span></>)}
              {fact("Last observed", <>{s.observed.last ? ago(s.observed.last) : "never"}<span className="block text-xs text-muted">{s.last_changed_at ? `content changed ${ago(s.last_changed_at)}` : "no change recorded"}</span></>)}
              {fact("Pages discovered", <>{s.observed.pages.toLocaleString()}<span className="block text-xs text-muted">{s.language_name ? `mostly ${s.language_name}` : "language not determined"} · trust {s.trust}</span></>)}
            </dl>
            <div className="border-t border-line px-4 py-3">
              <div className="mb-1.5 flex items-baseline justify-between text-xs"><span className="font-semibold text-ink-2">Availability, last 30 days</span>
                <span className="text-muted">{s.availability.percent === null ? "not checked in this period" : `answered ${s.availability.percent}% of ${s.availability.checks_30d} checks`}</span></div>
              {s.availability.days.length === 0 ? <p className="text-xs text-muted">No checks recorded yet.</p> : (
                <div className="flex flex-wrap gap-1" role="img" aria-label={`Availability by day: ${s.availability.days.map((d) => `${day(d.date)} ${d.answered}/${d.checks}`).join(", ")}`}>
                  {s.availability.days.map((d) => {
                    const up = d.answered === d.checks, down = d.answered === 0;
                    return <span key={d.date} title={`${day(d.date)}: answered ${d.answered} of ${d.checks} checks`} className={cn("flex h-6 w-6 items-center justify-center rounded text-2xs font-semibold", up ? "bg-good-soft text-good" : down ? "bg-critical-soft text-critical" : "bg-warning-soft text-warning")}>{up ? "✓" : down ? "×" : "~"}</span>;
                  })}
                </div>
              )}
              {s.last_error && <p className="mt-2 break-words text-xs text-muted">Last problem: {s.last_error}</p>}
            </div>
          </Card>

          <Card>
            <div className="px-3 pt-1"><Tabs value={tab} onChange={setTab} tabs={[
              { id: "pages", label: "Pages and observations", count: s.observed.pages }, { id: "related", label: "Related sources", count: s.links_out.length + s.links_in.length },
              { id: "history", label: "Collection history", count: s.runs.length }, { id: "notes", label: "Research notes" },
            ]} /></div>
            {tab === "pages" && (s.pages.length === 0 ? <Empty title="Nothing collected from this source yet" hint={s.status === "approved" ? "Its first crawl may still be running." : "Start a research crawl, or monitor it, to collect what it publishes."} action={canWrite && site && s.status !== "blocked" ? <CrawlButton url={s.url} label="Start research crawl" size="md" /> : undefined} />
              : <>{s.pages.map((f) => <FindingRow key={f.id} f={f} extra={<div className="mt-1 flex flex-wrap items-center gap-x-3 text-xs text-muted">
                <span>First seen {day(f.first_seen)} · last seen {ago(f.last_seen)}</span>{f.version_count > 1 && <Badge>{f.version_count} versions</Badge>}
                {f.missing && <Badge tone="warning" title="The site has been crawled since and this page was no longer reachable. The stored copy remains.">No longer on the site</Badge>}</div>} />)}
                {s.observed.pages > s.pages.length && <p className="border-t border-line px-4 py-2 text-xs text-muted">Showing the {s.pages.length} most recently seen of {s.observed.pages}. <Link className="link" href={`/search?q=${encodeURIComponent(`site:${s.host}`)}`}>Search them all</Link></p>}</>)}
            {tab === "related" && (s.links_out.length + s.links_in.length === 0 ? <Empty title="No links to or from other sources recorded" hint="Links are recorded as pages are crawled." /> : (
              <div className="grid gap-0 md:grid-cols-2 md:divide-x md:divide-line">
                {([["Links to", s.links_out.map((l) => ({ ...l, key: l.host })), true], ["Linked from", s.links_in.map((l) => ({ ...l, host: l.source.host, key: String(l.source.id) })), false]] as const).map(([title, rows, outbound]) => (
                  <div key={title}>
                    <div className="label border-b border-line bg-sunken px-4 py-1.5">{title} · {rows.length}</div>
                    {rows.length === 0 ? <p className="px-4 py-3 text-sm text-muted">None recorded.</p> : (
                      <ul className="divide-y divide-line">{rows.map((l) => (
                        <li key={l.key} className="flex items-center gap-2 px-4 py-2 text-sm">
                          {outbound ? <ArrowRight className="h-3.5 w-3.5 shrink-0 text-muted" /> : <ArrowLeft className="h-3.5 w-3.5 shrink-0 text-muted" />}
                          <div className="min-w-0 flex-1">{l.source ? <Link href={`/sources/${l.source.id}`} className="block truncate hover:underline">{l.source.title || l.source.name}</Link> : <span className="block truncate text-ink-2">Not on file</span>}
                            <div className="truncate font-mono text-2xs text-muted">{defang(shortHost(l.host))}</div></div>
                          {l.source && <StateBadge state={l.source.state} />}
                          <span className="shrink-0 text-2xs text-muted" title={`Last seen ${stamp(l.last_seen)}`}>{l.count}×</span>
                        </li>
                      ))}</ul>
                    )}
                  </div>
                ))}
              </div>
            ))}
            {tab === "history" && (s.runs.length === 0 ? <Empty title="No crawls yet" /> : (
              <table className="w-full"><thead><tr className="border-b border-line"><th className="th">When</th><th className="th text-right">Pages fetched</th><th className="th text-right">Read</th><th className="th text-right">New</th><th className="th text-right">Changed</th></tr></thead>
                <tbody className="divide-y divide-line">{s.runs.map((r) => {
                  const job = s.crawls.find((j) => j.progress && j.created_at && Math.abs(new Date(j.created_at).getTime() - new Date(r.at).getTime()) < 120000);
                  return <tr key={r.run_id}><td className="td whitespace-nowrap text-xs">{stamp(r.at)}{job && <Link className="link ml-2" href={`/crawls/${job.id}`}>research crawl #{job.id}</Link>}</td><td className="td text-right tabular-nums">{r.fetched}</td><td className="td text-right tabular-nums">{r.ok}</td><td className="td text-right tabular-nums">{r.new}</td><td className="td text-right tabular-nums">{r.changed}</td></tr>;
                })}</tbody></table>
            ))}
            {tab === "notes" && <div className="px-4 py-3">{s.notes && <p className="mb-3 whitespace-pre-wrap rounded-md bg-sunken px-3 py-2 text-xs text-ink-2">{s.notes}</p>}<Notes objectType="source" objectId={String(s.id)} /></div>}
          </Card>
        </div>

        <aside className="min-w-0 space-y-4">
          {actors.length > 0 && <Card><CardHeader title="Related actors and malware" hint="Named in what was collected here" /><div className="p-3"><BarList items={actors.slice(0, 12).map((e) => ({ key: String(e.id), label: e.name, value: e.count, href: `/entities/${e.id}`, hint: ENTITY_LABELS[e.type] }))} /></div></Card>}
          {others.length > 0 && <Card><CardHeader title="Organisations and other entities" /><div className="p-3"><BarList items={others.slice(0, 12).map((e) => ({ key: String(e.id), label: e.name, value: e.count, href: `/entities/${e.id}`, hint: ENTITY_LABELS[e.type] }))} /></div></Card>}
          <Card>
            <CardHeader title="How it is collected" />
            <dl className="space-y-2 px-4 py-3 text-sm">
              {fact("Route", s.route === "tor" ? "Through the Tor gateway" : "Allowlisted direct proxy")}
              {fact("Schedule", s.status === "approved" ? `Every ${s.crawl_interval_minutes >= 60 ? `${Math.round(s.crawl_interval_minutes / 60)} hours` : `${s.crawl_interval_minutes} minutes`}, ${s.max_depth} link${s.max_depth === 1 ? "" : "s"} deep, up to ${s.max_pages} pages` : "Not scheduled")}
              {s.connector === "html" && fact("JavaScript", <span className="flex items-center justify-between gap-2">
                <span>{s.render_js ? "Rendered in a disposable browser" : "Not run (plain fetch)"}</span>
                {canWrite && <button className="text-xs text-accent-ink hover:underline" onClick={() => patch({ render_js: !s.render_js }, s.render_js ? "Pages will be fetched without JavaScript" : "Pages will be rendered with JavaScript from the next crawl")}>{s.render_js ? "Turn off" : "Turn on"}</button>}
              </span>)}
              {fact("Last checked", s.last_checked_at ? ago(s.last_checked_at) : "never")}
              {fact("Last crawled", s.last_crawled_at ? ago(s.last_crawled_at) : "never")}
            </dl>
          </Card>
        </aside>
      </div>
    </>
  );
}

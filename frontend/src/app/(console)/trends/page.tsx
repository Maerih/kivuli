"use client";

import { ArrowDownRight, ArrowUpRight, ChevronRight, FileText, TrendingUp } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { FindingRow, SeverityBadge } from "@/components/bits";
import { BarList, ColumnChart } from "@/components/charts";
import { WorldMap } from "@/components/worldmap";
import { PageHeader } from "@/components/shell";
import { useSession } from "@/components/session";
import { Button, Card, CardHeader, Empty, ErrorNote, Spinner } from "@/components/ui";
import { useApi, type Bucket, type FindingSummary } from "@/lib/api";
import { ago, cn, compact, num } from "@/lib/format";

interface Dashboard {
  days: number; total: number; in_window: number; prev_window: number; last_24h: number; with_credentials: number;
  severity: Bucket[]; types: Bucket[]; countries: Bucket[]; country_map?: (Bucket & { numeric?: string })[]; actors: Bucket[]; organizations: Bucket[]; sectors: Bucket[];
  timeline: { date: string; count: number; high: number }[];
  focus_countries: { code: string; name: string }[];
  top_findings: FindingSummary[];
  open_alerts: { total: number; compromise: number; by_severity: Record<string, number>; recent: { id: number; severity: string; category: string; matched: string; created_at: string; watchlist: string; finding_id: string | null; title: string; priority: number }[] };
  sources: { by_status: Record<string, number>; approved: number; live: number; failing: number };
  counts: { watchlists: number; open_cases: number; iocs: number; actors: number };
  movers?: { actors: Mover[]; sectors: Mover[]; techniques: Mover[] };
  exposure?: { identities_open: number; hosts: number; hosts_at_risk: number; vulnerabilities_priority: number; vulnerabilities_exposed: number };
}
interface Mover { value: string; count: number; previous: number; change: number }

function Movers({ title, rows, href, label }: { title: string; rows: Mover[]; href: (value: string) => string; label?: (value: string) => string }) {
  const rising = rows.filter((r) => r.change > 0).slice(0, 5);
  return (
    <div className="min-w-0">
      <div className="label mb-1.5">{title}</div>
      {rising.length === 0 ? <p className="text-sm text-muted">Nothing rising.</p> : (
        <ul className="space-y-1">
          {rising.map((r) => (
            <li key={r.value} className="flex items-center gap-2 text-sm">
              <Link href={href(r.value)} className="min-w-0 flex-1 truncate hover:underline">{label ? label(r.value) : r.value}</Link>
              <span className="shrink-0 text-xs tabular-nums text-muted" title={`${r.count} findings in this period, ${r.previous} in the one before`}>{r.previous} → {r.count}</span>
              <span className="inline-flex w-12 shrink-0 items-center justify-end text-xs font-medium tabular-nums text-serious"><ArrowUpRight className="h-3 w-3" />{r.previous ? `${Math.round((r.change / r.previous) * 100)}%` : "new"}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function Tile({ label, value, sub, href, delta }: { label: string; value: string; sub?: string; href?: string; delta?: { pct: number; upIsBad: boolean } | null }) {
  const body = (
    <div className="card h-full px-4 py-3.5 transition hover:border-line-strong">
      <div className="text-xs font-medium text-muted">{label}</div>
      <div className="mt-1 flex items-baseline gap-2">
        <span className="text-2xl font-semibold tracking-tight">{value}</span>
        {delta && Number.isFinite(delta.pct) && delta.pct !== 0 && (
          <span className={cn("inline-flex items-center text-xs font-medium", delta.pct > 0 === delta.upIsBad ? "text-serious" : "text-good")}>
            {delta.pct > 0 ? <ArrowUpRight className="h-3.5 w-3.5" /> : <ArrowDownRight className="h-3.5 w-3.5" />}{Math.abs(delta.pct)}%
          </span>
        )}
      </div>
      {sub && <div className="mt-0.5 truncate text-xs text-muted">{sub}</div>}
    </div>
  );
  return href ? <Link href={href} className="block">{body}</Link> : body;
}

export default function TrendsPage() {
  const { meta } = useSession();
  const [days, setDays] = useState(30);
  const { data, error, isLoading } = useApi<Dashboard>(`/dashboard?days=${days}`, { refreshInterval: 120000 });

  if (isLoading && !data) return <Spinner />;
  if (error || !data) return <ErrorNote error={error ?? { message: "Dashboard unavailable" }} />;

  const pct = data.prev_window ? Math.round(((data.in_window - data.prev_window) / data.prev_window) * 100) : NaN;
  const columns = data.timeline.map((t) => ({
    label: new Date(t.date).toLocaleDateString("en-GB", { day: "numeric", month: "short" }),
    values: [t.count - t.high, t.high],
  }));
  const focus = data.focus_countries[0];

  return (
    <>
      <PageHeader
        title="Trends"
        subtitle={`${num(data.total)} findings collected across ${data.sources.approved} active sources.`}
        actions={<>
          <a href={`/api/reports/executive?days=${days}`} target="_blank" rel="noopener"><Button title="A printable summary of the period for leadership"><FileText className="h-3.5 w-3.5" /> Executive brief</Button></a>
          <div className="flex rounded-md border border-line-strong bg-raised p-0.5" role="group" aria-label="Time range">
            {[7, 30, 90].map((d) => (
              <button key={d} onClick={() => setDays(d)} aria-pressed={days === d} className={cn("rounded px-2.5 py-1 text-xs font-medium", days === d ? "bg-accent-soft text-accent-ink" : "text-ink-2 hover:text-ink")}>{d} days</button>
            ))}
          </div>
        </>}
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <Tile label={`Findings, last ${days} days`} value={compact(data.in_window)} sub={`${num(data.last_24h)} new in the last 24 hours`} href={`/search?from=${new Date(Date.now() - days * 864e5).toISOString().slice(0, 10)}`} delta={Number.isFinite(pct) ? { pct, upIsBad: true } : null} />
        <Tile label="Open alerts" value={num(data.open_alerts.total)} sub={`${data.open_alerts.compromise} possible compromise`} href="/alerts" />
        <Tile label="Credential exposures" value={num(data.with_credentials)} sub="Findings containing passwords" href="/search?creds=true" />
        <Tile label="Sources live" value={`${data.sources.live}/${data.sources.approved}`} sub={data.sources.failing ? `${data.sources.failing} failing` : `${data.sources.by_status.candidate ?? 0} candidates to review`} href="/sources" />
        <Tile label="Tracked" value={compact(data.counts.iocs)} sub={`indicators · ${num(data.counts.actors)} active actors`} href="/indicators" />
      </div>

      {data.exposure && (
        <div className="mt-3 grid grid-cols-2 gap-3 lg:grid-cols-4">
          <Tile label="Identity exposures open" value={num(data.exposure.identities_open)} sub="Accounts and secrets seen in leaks" href="/exposures" />
          <Tile label="Hosts at risk" value={`${num(data.exposure.hosts_at_risk)}/${num(data.exposure.hosts)}`} sub="Of your discovered attack surface" href="/attack-surface" />
          <Tile label="Vulnerabilities on your hosts" value={num(data.exposure.vulnerabilities_exposed)} sub="Reported by public scan data" href="/vulnerabilities" />
          <Tile label="Priority vulnerabilities" value={num(data.exposure.vulnerabilities_priority)} sub="Exploited, likely, or relevant to you" href="/vulnerabilities" />
        </div>
      )}

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader title="Findings over time" hint="By the date the source reported them" />
          <div className="px-4 py-4">
            <ColumnChart data={columns} height={220} caption={`Findings per day over the last ${days} days`} series={[{ name: "Other findings", color: "var(--series-1)" }, { name: "High and critical", color: "var(--series-2)" }]} />
          </div>
        </Card>
        <Card>
          <CardHeader title="Open alerts" action={<Link href="/alerts" className="link inline-flex items-center text-xs">Queue <ChevronRight className="h-3 w-3" /></Link>} />
          {data.open_alerts.recent.length === 0 ? (
            <Empty title="No open alerts" hint="Add a domain, email address or keyword to a watchlist to be alerted when it appears." action={<Link href="/watchlists" className="link text-sm">Set up a watchlist</Link>} />
          ) : (
            <ul className="divide-y divide-line">
              {data.open_alerts.recent.map((a) => (
                <li key={a.id} className="px-4 py-2.5">
                  <div className="flex items-center gap-2"><SeverityBadge severity={a.severity} /><span className="truncate text-sm font-medium">{a.matched}</span></div>
                  {a.finding_id ? <Link href={`/findings/${a.finding_id}`} className="mt-0.5 line-clamp-1 text-xs text-ink-2 hover:underline">{a.title}</Link> : <Link href="/alerts" className="mt-0.5 line-clamp-1 text-xs text-ink-2 hover:underline">{a.title}</Link>}
                  <div className="mt-0.5 text-2xs text-muted">{a.category === "compromise" ? "Possible compromise" : a.category === "attack_surface" ? "Attack surface" : a.category === "rule" ? "Detection rule" : a.category === "lookalike" ? "Look-alike domain" : "Match"} · {a.watchlist} · {ago(a.created_at)}</div>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <Card className="mt-4">
        <CardHeader title="Where it is happening" hint={`Countries named in findings over the last ${days} days. Click a country to open its findings.`} />
        <div className="px-4 py-4">
          {(data.country_map ?? []).length ? <WorldMap data={data.country_map ?? []} caption={`Findings per country over the last ${days} days`} />
            : <p className="text-sm text-muted">No country has been named in findings in this period.</p>}
        </div>
      </Card>

      <div className="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <Card>
          <CardHeader title="Threat types" />
          <div className="p-3"><BarList items={data.types.map((b) => ({ key: b.value, label: b.label ?? b.value, value: b.count, href: `/search?type=${b.value}` }))} /></div>
        </Card>
        <Card>
          <CardHeader title="Countries" action={focus && <Link href={`/search?country=${focus.code}`} className="link text-xs">{focus.name} only</Link>} />
          <div className="p-3"><BarList items={data.countries.map((b) => ({ key: b.value, label: b.label ?? b.value, value: b.count, href: `/search?country=${b.value}` }))} /></div>
        </Card>
        <Card>
          <CardHeader title="Most active actors" />
          <div className="p-3"><BarList items={data.actors.map((b) => ({ key: b.value, label: b.value, value: b.count, href: `/search?actor=${encodeURIComponent(b.value)}` }))} /></div>
        </Card>
        <Card>
          <CardHeader title="Sectors targeted" />
          <div className="p-3"><BarList items={data.sectors.map((b) => ({ key: b.value, label: b.value, value: b.count, href: `/search?sector=${encodeURIComponent(b.value)}` }))} /></div>
        </Card>
      </div>

      {data.movers && (data.movers.actors.length + data.movers.sectors.length + data.movers.techniques.length > 0) && (
        <Card className="mt-4">
          <CardHeader title={<span className="inline-flex items-center gap-1.5"><TrendingUp className="h-3.5 w-3.5" />What is rising</span>} hint={`Last ${days} days against the ${days} days before`} />
          <div className="grid gap-6 px-4 py-3 md:grid-cols-3">
            <Movers title="Threat actors" rows={data.movers.actors} href={(v) => `/search?actor=${encodeURIComponent(v)}`} />
            <Movers title="Sectors targeted" rows={data.movers.sectors} href={(v) => `/search?sector=${encodeURIComponent(v)}`} />
            <Movers title="ATT&CK techniques" rows={data.movers.techniques} href={(v) => `/attack/${v}`} label={(v) => `${v} ${meta.techniques?.[v] ?? ""}`.trim()} />
          </div>
        </Card>
      )}

      <Card className="mt-4">
        <CardHeader title="Highest-risk findings" hint={`Last ${days} days, duplicates removed`} action={<Link href="/search?sort=risk" className="link inline-flex items-center text-xs">All by risk <ChevronRight className="h-3 w-3" /></Link>} />
        {data.top_findings.length === 0 ? <Empty title="Nothing collected yet" hint="The first crawl starts within a minute of the stack coming up. Check Sources for progress." /> : data.top_findings.map((f) => <FindingRow key={f.id} f={f} />)}
      </Card>
    </>
  );
}

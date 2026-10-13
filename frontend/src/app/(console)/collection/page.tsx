"use client";

import { ShieldCheck, Square } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { CrawlButton, StateBadge } from "@/components/bits";
import { PageHeader } from "@/components/shell";
import { useSession } from "@/components/session";
import { Badge, Button, Card, CardHeader, Empty, ErrorNote, Field, Spinner, useAction } from "@/components/ui";
import { api, useApi, type CollectionStatus, type CrawlJob } from "@/lib/api";
import { ago, cn, defang, num, shortHost, stamp } from "@/lib/format";

interface Policy { values: CollectionStatus["policy"]; auto_approve_options: Record<string, string>; can_edit: boolean }
const JOB_TONE = { running: "accent", done: "good", stopped: "neutral", failed: "critical" } as const;
const STATES = ["online", "degraded", "offline", "unknown"] as const;

function Line({ label, value, state }: { label: string; value: React.ReactNode; state?: "ok" | "bad" }) {
  return (
    <div className="flex items-baseline justify-between gap-4 border-b border-line px-4 py-2 font-mono text-xs last:border-b-0">
      <span className="uppercase tracking-wide text-ink-2">{label}</span>
      <span className={cn("text-right text-sm font-semibold tabular-nums", state === "ok" && "text-good", state === "bad" && "text-critical")}>{value}</span>
    </div>
  );
}

function CrawlRow({ job, onStop }: { job: CrawlJob; onStop?: (job: CrawlJob) => void }) {
  const p = job.progress;
  return (
    <li className="flex flex-wrap items-center gap-x-4 gap-y-1 px-4 py-2.5">
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-1.5"><Badge tone={JOB_TONE[job.status]}>{job.status === "running" ? "Running" : job.status === "done" ? "Finished" : job.status === "stopped" ? "Stopped" : "Failed"}</Badge>
          <Link href={`/crawls/${job.id}`} className="min-w-0 truncate font-mono text-xs font-medium hover:underline" title={defang(job.url)}>{defang(job.url.length > 70 ? `${job.url.slice(0, 68)}…` : job.url)}</Link></div>
        <div className="mt-0.5 text-xs text-muted">Depth {job.depth} · limit {job.max_pages} pages · {p.fetched} fetched{p.failed ? `, ${p.failed} failed` : ""} · {p.new} new, {p.changed} changed{job.status === "running" && p.queued ? ` · ${p.queued} in progress` : ""} · started {ago(job.created_at)}{job.created_by ? ` by ${job.created_by}` : ""}</div>
      </div>
      <div className="flex gap-1">
        <Link href={`/crawls/${job.id}`}><Button size="sm">{job.status === "running" ? "Watch" : "Open"}</Button></Link>
        {onStop && job.status === "running" && <Button size="sm" variant="ghost" title="Stop queuing further pages" onClick={() => onStop(job)}><Square className="h-3.5 w-3.5" /></Button>}
      </div>
    </li>
  );
}

export default function CollectionPage() {
  const { canWrite } = useSession();
  const { data: c, error } = useApi<CollectionStatus>("/collection/status", { refreshInterval: 10000 });
  const { data: jobs, mutate: reloadJobs } = useApi<CrawlJob[]>("/crawls", { refreshInterval: 5000 });
  const { data: policy, mutate: reloadPolicy } = useApi<Policy>("/settings/collection");
  const [draft, setDraft] = useState<Partial<CollectionStatus["policy"]>>({});
  const { busy, run } = useAction();
  const stop = (job: CrawlJob) => run(() => api(`/crawls/${job.id}/stop`, { method: "POST" }), "Stopping: pages already being fetched will finish").then(() => reloadJobs());
  const values = { ...(policy?.values ?? {}), ...draft } as CollectionStatus["policy"];
  const dirty = Object.keys(draft).length > 0;
  const save = () => run(() => api("/settings/collection", { method: "PUT", body: draft }), "Collection policy saved. Waiting sites are being re-checked against it.").then((ok) => { if (ok) { setDraft({}); reloadPolicy(); } });
  const number = (key: keyof CollectionStatus["policy"], label: string, hint: string, min: number, max: number) => (
    <Field label={label} hint={hint}><input className="field" type="number" min={min} max={max} disabled={!policy?.can_edit} value={values[key] as number} onChange={(e) => setDraft({ ...draft, [key]: Math.max(min, Math.min(max, Number(e.target.value) || min)) })} /></Field>
  );

  return (
    <>
      <PageHeader title="Collection and crawls" subtitle="Whether the Tor collection layer is healthy, what it is doing right now, and the research crawls you have started. Collection runs in isolated workers; this console only asks them to work and reads what they stored."
        actions={<><Link href="/sources"><Button>Source explorer</Button></Link><CrawlButton label="Start research crawl" size="md" /></>} />
      <ErrorNote error={error} />
      {!c ? <Spinner /> : (
        <div className="grid gap-4 xl:grid-cols-[22rem_minmax(0,1fr)]">
          <div className="space-y-4">
            <Card>
              <CardHeader title="Collection status" hint="Refreshes every ten seconds" />
              <Line label="Tor connection" value={c.tor.online ? "ONLINE" : "OFFLINE"} state={c.tor.online ? "ok" : "bad"} />
              <Line label="Collectors" value={`${c.collectors.online}/${c.collectors.expected}`} state={c.collectors.online === c.collectors.expected ? "ok" : "bad"} />
              <Line label="Active sources" value={<>{num(c.sources.active)} <span className="font-sans text-2xs font-normal text-muted">({num(c.sources.active_onion)} Tor)</span></>} />
              <Line label="Offline sources" value={num(c.sources.offline)} state={c.sources.offline ? "bad" : undefined} />
              <Line label="Crawl queue" value={num(c.queue.crawl + c.queue.pipeline)} />
              <Line label="Pages indexed" value={<>{num(c.pages.indexed)} <span className="font-sans text-2xs font-normal text-muted">({num(c.pages.onion)} Tor)</span></>} />
              <Line label="Last collection" value={c.last_collection ? ago(c.last_collection) : "never"} />
              <Line label="Failed fetches, 24 h" value={`${num(c.failed_24h)} of ${num(c.fetches_24h)}`} />
              <p className="border-t border-line px-4 py-2 text-xs text-muted">{c.tor.online ? <>Exiting through Tor at {c.tor.exit_ip}, checked {ago(c.tor.checked_at)}.</> : <>Tor is not ready: {c.tor.error || "no check has completed"}.</>} Workers: {Object.entries(c.collectors.roles).map(([role, n]) => `${role} ${n ? "up" : "DOWN"}`).join(", ")}.</p>
            </Card>

            <Card>
              <CardHeader title="Source health" hint="Sources being collected, by whether they answer" />
              <table className="w-full"><thead><tr className="border-b border-line"><th className="th">Network</th>{STATES.map((s) => <th key={s} className="th text-right"><StateBadge state={s} /></th>)}</tr></thead>
                <tbody className="divide-y divide-line">{(["onion", "surface"] as const).map((net) => (
                  <tr key={net}><td className="td text-sm">{net === "onion" ? "Tor" : "Web"}</td>{STATES.map((s) => <td key={s} className="td text-right tabular-nums">{c.sources.states[net]?.[s] ?? 0}</td>)}</tr>
                ))}</tbody></table>
              <p className="border-t border-line px-4 py-2 text-xs text-muted">{num(c.sources.candidates)} discovered sites are waiting ({num(c.sources.candidates_onion)} on Tor), {num(c.sources.blocked)} blocked. <Link className="link" href="/sources">Open the explorer</Link></p>
            </Card>

            <Card>
              <CardHeader title="Safety controls" />
              <div className="space-y-2 px-4 py-3 text-xs text-ink-2">
                <p className="flex items-start gap-2"><ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-good" /><span><span className="font-semibold">{num(c.blocklist.count)}</span> onion services banned for abuse material are never fetched{c.blocklist.updated_at ? ` (list refreshed ${ago(c.blocklist.updated_at)})` : " (list not loaded yet)"}. Only hashes are kept.</span></p>
                <p className="flex items-start gap-2"><ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-good" /><span>Text only, read only: no logins, no CAPTCHA solving, no downloads of archives, media or attachments, no scripts run. Leaked secrets are redacted before storage.</span></p>
              </div>
            </Card>
          </div>

          <div className="min-w-0 space-y-4">
            <Card>
              <CardHeader title="Research crawls" hint="Started by a researcher from one URL. Each stays on the site it started on." action={<CrawlButton label="New crawl" />} />
              {!jobs ? <Spinner /> : jobs.length === 0 ? <Empty title="No research crawls yet" hint="Give the crawler a starting address and a depth. It follows links on that site, stores every page it reads with its history, and records other sites it finds as new sources." action={<CrawlButton label="Start research crawl" size="md" />} />
                : <ul className="divide-y divide-line">{jobs.map((j) => <CrawlRow key={j.id} job={j} onStop={canWrite ? stop : undefined} />)}</ul>}
            </Card>

            <Card>
              <CardHeader title="Collection policy" hint="What happens when a new onion site is discovered" action={policy?.can_edit && dirty && <Button size="sm" variant="primary" busy={busy} onClick={save}>Save</Button>} />
              {!policy ? <Spinner /> : (
                <div className="space-y-4 px-4 py-3">
                  <fieldset className="space-y-2" disabled={!policy.can_edit}>
                    <legend className="mb-1 text-xs font-medium text-ink-2">Start collecting automatically</legend>
                    {Object.entries(policy.auto_approve_options).map(([key, text]) => (
                      <label key={key} className="flex cursor-pointer items-start gap-2 text-sm"><input type="radio" name="auto_approve" className="mt-1 accent-[var(--accent)]" checked={values.auto_approve === key} onChange={() => setDraft({ ...draft, auto_approve: key })} />
                        <span><span className="font-medium">{key === "manual" ? "Never" : key === "leak_sites" ? "Leak sites" : "Leak sites and relevant sites"}</span> <span className="text-muted">· {text}</span></span></label>
                    ))}
                  </fieldset>
                  <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                    {values.auto_approve === "relevant" && number("relevance_threshold", "Relevance needed (1-10)", "Scored from the site's own title when it is first checked.", 1, 10)}
                    {number("max_onion_sources", "Most onion sources collected automatically", "A ceiling, so discovery cannot run away.", 0, 5000)}
                    {number("discovery_groups_per_run", "Groups looked up per discovery run", "Leak-site lookups for active ransomware groups.", 1, 40)}
                    {number("research_max_depth", "Deepest research crawl", "Largest depth a researcher may choose.", 1, 6)}
                    {number("research_max_pages", "Largest research crawl (pages)", "Largest page limit a researcher may choose.", 5, 2000)}
                  </div>
                  <p className="text-xs text-muted">{policy.can_edit ? "Sites found through links on other sites always stay reviewable in the source explorer; you can approve any of them by hand." : "Only administrators can change the policy."} Sites on the abuse blocklist are refused under every policy.</p>
                </div>
              )}
            </Card>
            <p className="text-xs text-muted">Tor checked {c.tor.checked_at ? stamp(c.tor.checked_at) : "never"}. Queue: {c.queue.crawl} fetches, {c.queue.pipeline} to process, {c.queue.enrich} lookups. Hosts are shown defanged, for example <span className="font-mono">{defang(shortHost("example.onion"))}</span>.</p>
          </div>
        </div>
      )}
    </>
  );
}

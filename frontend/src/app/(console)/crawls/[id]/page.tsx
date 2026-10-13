"use client";

import { ArrowLeft, CheckCircle2, ChevronRight, FileText, Loader2, Square, XCircle } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useMemo, useState } from "react";
import { AddToCase, CrawlButton, RiskMeter, StateBadge } from "@/components/bits";
import { PageHeader } from "@/components/shell";
import { useSession } from "@/components/session";
import { Badge, Button, Card, CardHeader, Empty, ErrorNote, Spinner, useAction } from "@/components/ui";
import { api, useApi, type CrawlJob, type SourceBrief } from "@/lib/api";
import { ago, cn, defang, shortHost, SOURCE_KIND_LABELS, stamp } from "@/lib/format";

interface Page { url: string; parent: string; depth: number; ok: boolean; http_status: number | null; error: string; fetched_at: string; bytes: number; new: number; changed: number; finding_id: string | null; title: string; risk_score: number | null }
interface Detail extends CrawlJob { pages: Page[]; discovered_sources: SourceBrief[] }

const path = (url: string) => { try { const u = new URL(url); return (u.pathname + u.search) || "/"; } catch { return url; } };

export default function CrawlPage() {
  const { id } = useParams<{ id: string }>();
  const { canWrite } = useSession();
  const [live, setLive] = useState(true);
  const { data: job, error, mutate } = useApi<Detail>(`/crawls/${id}`, { refreshInterval: live ? 2500 : 0, onSuccess: (d) => setLive(d.status === "running") });
  const [open, setOpen] = useState<Set<number>>(new Set([0, 1]));
  const { busy, run } = useAction();
  const byDepth = useMemo(() => {
    const groups = new Map<number, Page[]>();
    (job?.pages ?? []).forEach((p) => groups.set(p.depth, [...(groups.get(p.depth) ?? []), p]));
    return [...groups.entries()].sort((a, b) => a[0] - b[0]);
  }, [job]);
  if (error) return <><Link href="/collection" className="mb-3 inline-flex items-center gap-1 text-xs text-muted hover:text-ink"><ArrowLeft className="h-3.5 w-3.5" /> Collection</Link><ErrorNote error={error} /></>;
  if (!job) return <Spinner />;
  const p = job.progress;
  const running = job.status === "running";
  const stored = job.pages.filter((x) => x.finding_id).length;
  const toggle = (d: number) => setOpen((s) => { const n = new Set(s); n.has(d) ? n.delete(d) : n.add(d); return n; });

  return (
    <>
      <Link href="/collection" className="mb-3 inline-flex items-center gap-1 text-xs text-muted hover:text-ink"><ArrowLeft className="h-3.5 w-3.5" /> Collection and crawls</Link>
      <PageHeader
        title={<span className="flex flex-wrap items-center gap-2">Research crawl #{job.id} {running ? <Badge tone="accent"><Loader2 className="h-3 w-3 animate-spin" />Running</Badge> : <Badge tone={job.status === "done" ? "good" : "neutral"}>{job.status === "done" ? "Finished" : job.status === "stopped" ? "Stopped" : "Failed"}</Badge>}</span>}
        subtitle={<><span className="break-all font-mono text-xs">{defang(job.url)}</span><span className="mt-0.5 block">Depth {job.depth}, up to {job.max_pages} pages, same site only · started {stamp(job.created_at)}{job.created_by ? ` by ${job.created_by}` : ""}{job.finished_at ? ` · ended ${ago(job.finished_at)}` : ""}</span></>}
        actions={<>
          <Link href={`/sources/${job.source.id}`}><Button>Source profile</Button></Link>
          <Link href={`/search?q=${encodeURIComponent(`site:${job.source.host}`)}`}><Button>Search what it found</Button></Link>
          {canWrite && running && <Button variant="danger" busy={busy} onClick={() => run(() => api(`/crawls/${job.id}/stop`, { method: "POST" }), "Stopping").then(() => mutate())}><Square className="h-3.5 w-3.5" /> Stop</Button>}
          {!running && <CrawlButton url={job.url} label="Crawl again" size="md" />}
        </>}
      />

      <div className="mb-4 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        {([["Pages reached", p.fetched], ["In progress", running ? p.queued : 0], ["Stored as findings", stored], ["New", p.new], ["Changed", p.changed], ["Failed", p.failed]] as const).map(([label, value]) => (
          <div key={label} className="card px-4 py-3"><div className="text-xs text-muted">{label}</div><div className={cn("mt-0.5 text-2xl font-semibold tabular-nums", label === "Failed" && value > 0 && "text-critical")}>{value}</div></div>
        ))}
      </div>
      {running && <div className="mb-4 h-1.5 overflow-hidden rounded-full bg-sunken" role="progressbar" aria-valuemin={0} aria-valuemax={job.max_pages} aria-valuenow={p.fetched} aria-label="Pages fetched of the page limit"><div className="h-full rounded-full bg-accent transition-all" style={{ width: `${Math.min(100, (100 * p.fetched) / Math.max(1, Math.min(job.max_pages, p.discovered || job.max_pages)))}%` }} /></div>}

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_21rem]">
        <Card className="min-w-0">
          <CardHeader title="Pages discovered" hint="By how many links from the starting page. Each page shows the page that led to it." />
          {job.pages.length === 0 ? <Empty title={running ? "Waiting for the first page" : "No pages were reached"} hint={running ? "Onion sites can take a minute to answer through Tor." : "The starting address did not answer. Check the source profile for the error."} /> : byDepth.map(([depth, pages]) => (
            <section key={depth} className="border-b border-line last:border-b-0">
              <button onClick={() => toggle(depth)} aria-expanded={open.has(depth)} className="flex w-full items-center gap-2 bg-sunken px-4 py-1.5 text-left text-xs font-semibold text-ink-2 hover:text-ink">
                <ChevronRight className={cn("h-3.5 w-3.5 transition-transform", open.has(depth) && "rotate-90")} />{depth === 0 ? "Starting page" : `Depth ${depth}`}
                <span className="font-normal text-muted">· {pages.length} page{pages.length === 1 ? "" : "s"} · {pages.filter((x) => x.ok).length} read</span>
              </button>
              {open.has(depth) && (
                <ul className="divide-y divide-line">
                  {pages.map((page, i) => (
                    <li key={i} className="flex items-start gap-2.5 px-4 py-2" style={{ paddingLeft: `${1 + Math.min(depth, 4) * 0.9}rem` }}>
                      {page.ok ? <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-good" aria-label="Read" /> : <XCircle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-critical" aria-label="Failed" />}
                      <div className="min-w-0 flex-1">
                        {page.finding_id ? <Link href={`/findings/${page.finding_id}`} className="block truncate text-sm font-medium hover:underline">{page.title || path(page.url)}</Link> : <span className="block truncate text-sm text-ink-2">{page.ok ? "Read, nothing worth storing (too little text, or an index page)" : page.error || "Failed"}</span>}
                        <div className="truncate font-mono text-2xs text-muted" title={defang(page.url)}>{defang(path(page.url))}{page.parent && <span className="font-sans"> · from {defang(path(page.parent))}</span>}</div>
                      </div>
                      <div className="flex shrink-0 items-center gap-1.5">
                        {page.new > 0 && <Badge tone="accent">New</Badge>}{page.changed > 0 && <Badge tone="warning">Changed</Badge>}
                        {page.risk_score !== null && <RiskMeter score={page.risk_score} />}
                        {page.finding_id && <AddToCase objectType="finding" objectId={page.finding_id} size="sm" label="Add" />}
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          ))}
        </Card>

        <aside className="min-w-0 space-y-4">
          <Card>
            <CardHeader title="Other sites it found" hint="Recorded as sources, not followed" />
            {job.discovered_sources.length === 0 ? <p className="px-4 py-3 text-sm text-muted">{running ? "None yet." : "This site did not link to any other onion service."}</p> : (
              <ul className="divide-y divide-line">
                {job.discovered_sources.map((s) => (
                  <li key={s.id} className="px-4 py-2">
                    <div className="flex items-center gap-2"><Link href={`/sources/${s.id}`} className="min-w-0 flex-1 truncate text-sm font-medium hover:underline">{s.title || s.name}</Link><StateBadge state={s.state} /></div>
                    <div className="truncate text-2xs text-muted"><span className="font-mono">{defang(shortHost(s.host))}</span> · {SOURCE_KIND_LABELS[s.category] ?? s.category} · {s.status === "approved" ? "collecting" : s.status}</div>
                  </li>
                ))}
              </ul>
            )}
          </Card>
          <Card className="px-4 py-3 text-xs leading-relaxed text-muted">
            <p className="mb-1 flex items-center gap-1.5 font-semibold text-ink-2"><FileText className="h-3.5 w-3.5" />What a crawl keeps</p>
            Every page that has enough text becomes a finding: its text with secrets redacted, the indicators and entities in it, a hash of the original, and a version each time it changes. A page that disappears later stays searchable. Images, archives and attachments are never downloaded.
          </Card>
        </aside>
      </div>
    </>
  );
}

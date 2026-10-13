"use client";

import { ArrowLeft, FileDown, FileText, Search, Share2, Sparkles, Trash2 } from "lucide-react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { AiLabel, AiSources, CitedText, CrawlButton, Defanged, FindingRow, Notes, PRIORITY_TONE, TlpBadge, useAiJob } from "@/components/bits";
import { PageHeader } from "@/components/shell";
import { useSession } from "@/components/session";
import { Badge, Button, Card, CardHeader, Empty, ErrorNote, Spinner, Tabs, useAction } from "@/components/ui";
import { api, useApi, type FindingSummary } from "@/lib/api";
import { ago, cn, ENTITY_LABELS, IOC_LABELS, stamp, titleCase } from "@/lib/format";

interface CaseDetail {
  id: number; title: string; description: string; status: string; priority: string; tlp: string; owner: string; owner_id: number | null;
  created_at: string; updated_at: string; closed_at: string | null;
  findings: (FindingSummary & { item_id: number; note: string; added_at: string; added_by: string })[];
  iocs: { id: number; type: string; value: string; shared: number; pinned: boolean }[];
  entities: { id: number; type: string; name: string; shared: number; pinned: boolean }[];
  pinned_items: { item_id: number; object_type: string; object_id: string }[];
  hunts: { item_id: number; kind: "query" | "graph"; ref: string; text: string; added_at: string; added_by: string }[];
  evidence: { item_id: number; finding_id: string; version: number; title: string; url: string; captured_at: string; content_sha256: string; raw_sha256: string; chain_hash: string; bytes: number; note: string; preserved_at: string; preserved_by: string }[];
  crawls: { id: number; url: string; status: string; depth: number; created_at: string }[];
}
interface TimelineEvent { at: string | null; kind: string; text: string; who?: string; finding_id?: string }
const EVENT: Record<string, { label: string; dot: string }> = {
  reported: { label: "Reported", dot: "bg-serious" }, collected: { label: "Collected", dot: "bg-accent" }, changed: { label: "Changed", dot: "bg-warning" },
  alert: { label: "Alert", dot: "bg-critical" }, added: { label: "Added", dot: "bg-ink-2" }, evidence: { label: "Evidence", dot: "bg-good" }, note: { label: "Note", dot: "bg-ink-2" }, status: { label: "Updated", dot: "bg-good" }, case: { label: "Case", dot: "bg-good" },
};

export default function CasePage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const { canWrite, isAdmin } = useSession();
  const { data: c, error, mutate } = useApi<CaseDetail>(`/cases/${id}`);
  const { data: people } = useApi<{ id: number; name: string }[]>("/users/directory");
  const [tab, setTab] = useState<"findings" | "iocs" | "entities" | "evidence" | "hunts" | "timeline" | "notes">("findings");
  const { data: timeline } = useApi<TimelineEvent[]>(tab === "timeline" ? `/cases/${id}/timeline` : null);
  const { data: ai } = useApi<{ enabled: boolean }>("/ai/status");
  const draft = useAiJob();
  const [summary, setSummary] = useState("");
  const [dirty, setDirty] = useState(false);
  const { busy, run } = useAction();

  useEffect(() => { if (c && !dirty) setSummary(c.description); }, [c, dirty]);
  if (error) return <ErrorNote error={error} />;
  if (!c) return <Spinner />;

  const patch = (body: Record<string, unknown>, message = "Saved") => run(() => api(`/cases/${id}`, { method: "PATCH", body }), message).then(() => mutate());
  const removeItem = (itemId: number) => run(() => api(`/cases/${id}/items/${itemId}`, { method: "DELETE" }), "Removed from case").then(() => mutate());
  const pinnedId = (type: string, objectId: number) => c.pinned_items.find((p) => p.object_type === type && p.object_id === String(objectId))?.item_id;
  const report = (format: string) => `/api/cases/${id}/report?format=${format}`;

  return (
    <>
      <Link href="/cases" className="mb-3 inline-flex items-center gap-1 text-xs text-muted hover:text-ink"><ArrowLeft className="h-3.5 w-3.5" /> All cases</Link>
      <PageHeader
        title={c.title}
        subtitle={<span className="flex flex-wrap items-center gap-2 pt-1"><Badge tone={PRIORITY_TONE[c.priority]}>{titleCase(c.priority)} priority</Badge><TlpBadge tlp={c.tlp} /><span>Case #{c.id} · opened {stamp(c.created_at)} · updated {ago(c.updated_at)}</span></span>}
        actions={<>
          <CrawlButton label="Research crawl" size="md" caseId={c.id} />
          <a href={report("html")} target="_blank" rel="noopener"><Button variant="primary"><FileText className="h-3.5 w-3.5" /> Report</Button></a>
          <a href={report("csv")}><Button title="Indicators as CSV"><FileDown className="h-3.5 w-3.5" /> CSV</Button></a>
          <a href={report("stix")}><Button title="STIX 2.1 bundle">STIX</Button></a>
          <a href={report("json")}><Button>JSON</Button></a>
        </>}
      />

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_20rem]">
        <div className="min-w-0 space-y-4">
          <Card>
            <CardHeader title="Summary" hint="Appears at the top of the exported report" action={canWrite && <>
              {ai?.enabled && c.findings.length > 0 && <Button size="sm" busy={draft.busy} title="Draft an executive summary from the attached findings" onClick={() => draft.start("/ai/brief", { case_id: c.id })}><Sparkles className="h-3.5 w-3.5" /> {draft.busy ? "Drafting" : "Draft with AI"}</Button>}
              {dirty && <Button size="sm" variant="primary" busy={busy} onClick={() => patch({ description: summary }).then(() => setDirty(false))}>Save</Button>}
            </>} />
            <div className="p-3">
              {canWrite
                ? <textarea className="field h-32 py-2" value={summary} placeholder="What happened, who is affected, what you recommend…" onChange={(e) => { setSummary(e.target.value); setDirty(true); }} />
                : <p className="whitespace-pre-wrap px-1 text-sm text-ink-2">{c.description || "No summary written."}</p>}
              {draft.job.status === "error" && <p className="mt-2 rounded-md bg-critical-soft px-3 py-2 text-sm text-critical" role="alert">{draft.job.error}</p>}
              {draft.job.status === "done" && draft.job.text && (
                <div className="mt-3 rounded-md border border-line bg-sunken px-3 py-2.5">
                  <CitedText text={draft.job.text} sources={draft.job.sources} />
                  <AiSources sources={draft.job.sources} cited={draft.job.citations} />
                  <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-line pt-2">
                    <AiLabel>Draft from the attached findings. Review it before it goes in a report.</AiLabel>
                    <span className="ml-auto flex gap-2">
                      <Button size="sm" onClick={() => draft.reset()}>Discard</Button>
                      <Button size="sm" variant="primary" onClick={() => { setSummary(summary.trim() ? `${summary.trim()}\n\n${draft.job.text}` : draft.job.text!); setDirty(true); draft.reset(); }}>Use as summary</Button>
                    </span>
                  </div>
                </div>
              )}
            </div>
          </Card>
          <Card>
            <div className="px-3 pt-1"><Tabs value={tab} onChange={setTab} tabs={[
              { id: "findings", label: "Findings", count: c.findings.length }, { id: "iocs", label: "Indicators", count: c.iocs.length },
              { id: "entities", label: "Actors and organisations", count: c.entities.length }, { id: "evidence", label: "Evidence", count: c.evidence.length },
              { id: "hunts", label: "Hunts, crawls and bookmarks", count: c.hunts.length + c.crawls.length },
              { id: "timeline", label: "Timeline" }, { id: "notes", label: "Notes" },
            ]} /></div>
            {tab === "findings" && (c.findings.length === 0 ? <Empty title="No findings attached" hint="Use “Add to case” on a search result or a finding page." action={<Link href="/search" className="link text-sm">Go to search</Link>} /> : c.findings.map((f) => (
              <FindingRow key={f.id} f={f} extra={<div className="mt-1 flex items-center gap-3 text-xs text-muted"><span>Added {ago(f.added_at)}{f.added_by ? ` by ${f.added_by}` : ""}</span>{canWrite && <button className="inline-flex items-center gap-1 hover:text-critical" onClick={() => removeItem(f.item_id)}><Trash2 className="h-3 w-3" />Remove</button>}</div>} />
            )))}
            {tab === "iocs" && (c.iocs.length === 0 ? <Empty title="No indicators yet" hint="Indicators from attached findings are collected here automatically." /> : (
              <div className="scroll-thin max-h-[560px] overflow-auto">
                <table className="w-full">
                  <thead className="sticky top-0 bg-surface"><tr><th className="th">Type</th><th className="th">Value</th><th className="th text-right">In findings</th><th className="th" /></tr></thead>
                  <tbody className="divide-y divide-line">
                    {c.iocs.map((i) => (
                      <tr key={i.id}>
                        <td className="td whitespace-nowrap text-xs text-muted">{IOC_LABELS[i.type] ?? i.type}</td>
                        <td className="td max-w-md"><Defanged value={i.value} />{i.pinned && <Badge className="ml-2">Pinned</Badge>}</td>
                        <td className="td text-right"><Link href={`/indicators/${i.id}`} className="link tabular-nums">{i.shared}</Link></td>
                        <td className="td text-right">{canWrite && i.pinned && <button aria-label="Unpin" className="text-muted hover:text-critical" onClick={() => removeItem(pinnedId("ioc", i.id)!)}><Trash2 className="h-3.5 w-3.5" /></button>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ))}
            {tab === "entities" && (c.entities.length === 0 ? <Empty title="No entities yet" /> : (
              <ul className="divide-y divide-line">
                {c.entities.map((e) => (
                  <li key={e.id} className="flex items-center gap-3 px-4 py-2.5 text-sm">
                    <Link href={`/entities/${e.id}`} className="min-w-0 flex-1 truncate hover:underline">{e.name}</Link>
                    {e.pinned && <Badge>Pinned</Badge>}
                    <span className="shrink-0 text-xs text-muted">{ENTITY_LABELS[e.type]} · {e.shared} finding{e.shared === 1 ? "" : "s"}</span>
                    {canWrite && e.pinned && <button aria-label="Unpin" className="text-muted hover:text-critical" onClick={() => removeItem(pinnedId("entity", e.id)!)}><Trash2 className="h-3.5 w-3.5" /></button>}
                  </li>
                ))}
              </ul>
            ))}
            {tab === "evidence" && (c.evidence.length === 0 ? <Empty title="No evidence preserved yet" hint="Open a finding and choose “Preserve evidence” to pin that exact capture, with its hashes, to this investigation." /> : (
              <ul className="divide-y divide-line">
                {c.evidence.map((ev) => (
                  <li key={ev.item_id} className="px-4 py-3">
                    <div className="flex items-start justify-between gap-3">
                      <Link href={`/findings/${ev.finding_id}?tab=evidence`} className="min-w-0 text-sm font-medium hover:underline">{ev.title || "Untitled capture"}</Link>
                      {canWrite && <button aria-label="Remove from the investigation" className="shrink-0 text-muted hover:text-critical" onClick={() => removeItem(ev.item_id)}><Trash2 className="h-3.5 w-3.5" /></button>}
                    </div>
                    <div className="mt-1"><Defanged value={ev.url} className="text-muted" /></div>
                    <dl className="mt-1.5 grid gap-x-6 gap-y-1 text-xs sm:grid-cols-2">
                      <div className="flex gap-2"><dt className="w-28 shrink-0 text-muted">Collected</dt><dd>{stamp(ev.captured_at)} · version {ev.version}</dd></div>
                      <div className="flex gap-2"><dt className="w-28 shrink-0 text-muted">Preserved</dt><dd>{stamp(ev.preserved_at)}{ev.preserved_by ? ` by ${ev.preserved_by}` : ""}</dd></div>
                      <div className="flex min-w-0 gap-2"><dt className="w-28 shrink-0 text-muted">Content SHA-256</dt><dd className="min-w-0 truncate font-mono" title={ev.content_sha256}>{ev.content_sha256}</dd></div>
                      <div className="flex min-w-0 gap-2"><dt className="w-28 shrink-0 text-muted">Original SHA-256</dt><dd className="min-w-0 truncate font-mono" title={ev.raw_sha256}>{ev.raw_sha256 || "n/a"}</dd></div>
                    </dl>
                    {ev.note && <p className="mt-1.5 whitespace-pre-wrap rounded bg-sunken px-2 py-1 text-xs text-ink-2">{ev.note}</p>}
                  </li>
                ))}
              </ul>
            ))}
            {tab === "hunts" && c.crawls.length > 0 && (
              <ul className="divide-y divide-line border-b border-line">
                {c.crawls.map((j) => <li key={j.id} className="flex items-center gap-3 px-4 py-2 text-sm"><Link href={`/crawls/${j.id}`} className="min-w-0 flex-1 truncate font-mono text-xs hover:underline">{j.url}</Link><span className="shrink-0 text-xs text-muted">research crawl · depth {j.depth} · {j.status} · {ago(j.created_at)}</span></li>)}
              </ul>
            )}
            {tab === "hunts" && (c.hunts.length === 0 ? <Empty title="No saved hunts or bookmarks" hint="Save a search from the search page with “Save hunt to case”, or bookmark a node from the relationship graph, to keep the pivots that led somewhere." /> : (
              <ul className="divide-y divide-line">
                {c.hunts.map((h) => (
                  <li key={h.item_id} className="flex items-center gap-3 px-4 py-2.5 text-sm">
                    {h.kind === "query" ? <Search className="h-4 w-4 shrink-0 text-muted" /> : <Share2 className="h-4 w-4 shrink-0 text-muted" />}
                    <div className="min-w-0 flex-1">
                      <Link href={h.kind === "query" ? `/search?q=${encodeURIComponent(h.text)}` : `/graph?node=${encodeURIComponent(h.ref)}`} className={cn("block truncate hover:underline", h.kind === "query" && "font-mono text-xs")}>{h.text || h.ref}</Link>
                      <div className="text-xs text-muted">{h.kind === "query" ? "Saved hunt: runs against current data" : "Graph bookmark"} · added {ago(h.added_at)}{h.added_by ? ` by ${h.added_by}` : ""}</div>
                    </div>
                    {canWrite && <button aria-label="Remove" className="text-muted hover:text-critical" onClick={() => removeItem(h.item_id)}><Trash2 className="h-3.5 w-3.5" /></button>}
                  </li>
                ))}
              </ul>
            ))}
            {tab === "timeline" && (!timeline ? <Spinner /> : (
              <ol className="relative px-4 py-3">
                {timeline.map((e, i) => (
                  <li key={i} className="relative flex gap-3 pb-4 last:pb-0">
                    {i < timeline.length - 1 && <span className="absolute left-[5px] top-3 h-full w-px bg-line" aria-hidden />}
                    <span className={cn("relative mt-1.5 h-[11px] w-[11px] shrink-0 rounded-full ring-2 ring-surface", EVENT[e.kind]?.dot ?? "bg-ink-2")} aria-hidden />
                    <div className="min-w-0 flex-1">
                      <div className="text-xs text-muted"><span className="font-semibold text-ink-2">{EVENT[e.kind]?.label ?? titleCase(e.kind)}</span> · {stamp(e.at)}{e.who ? ` · ${e.who}` : ""}</div>
                      {e.finding_id ? <Link href={`/findings/${e.finding_id}`} className="block break-words text-sm hover:underline">{e.text}</Link> : <p className="whitespace-pre-wrap break-words text-sm">{e.text}</p>}
                    </div>
                  </li>
                ))}
              </ol>
            ))}
            {tab === "notes" && <div className="px-4 py-3"><Notes objectType="case" objectId={String(c.id)} /></div>}
          </Card>
        </div>

        <aside>
          <Card>
            <CardHeader title="Case details" />
            <div className="space-y-3 px-4 py-3">
              {([["status", "Status", ["open", "in_progress", "closed"]], ["priority", "Priority", ["low", "medium", "high", "critical"]], ["tlp", "Sharing (TLP)", ["clear", "green", "amber", "red"]]] as const).map(([key, label, options]) => (
                <label key={key} className="block text-xs font-medium text-ink-2">{label}
                  <select disabled={!canWrite} className="field mt-1" value={c[key]} onChange={(e) => patch({ [key]: e.target.value })}>
                    {options.map((o) => <option key={o} value={o}>{key === "tlp" ? `TLP:${o.toUpperCase()}` : titleCase(o)}</option>)}
                  </select>
                </label>
              ))}
              <label className="block text-xs font-medium text-ink-2">Owner
                <select disabled={!canWrite} className="field mt-1" value={c.owner_id ?? ""} onChange={(e) => e.target.value && patch({ owner_id: Number(e.target.value) })}>
                  <option value="">Unassigned</option>{people?.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
                </select>
              </label>
              {c.closed_at && <p className="text-xs text-muted">Closed {stamp(c.closed_at)}</p>}
              {isAdmin && <Button variant="danger" size="sm" className="w-full" onClick={() => confirm("Delete this case? Findings themselves are kept.") && run(() => api(`/cases/${id}`, { method: "DELETE" }), "Case deleted").then((ok) => ok && router.push("/cases"))}><Trash2 className="h-3.5 w-3.5" /> Delete case</Button>}
            </div>
          </Card>
        </aside>
      </div>
    </>
  );
}

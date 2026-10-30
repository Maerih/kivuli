"use client";

import { Coins, ArrowLeft, Crosshair, Radio, RefreshCw, Share2, ShieldOff } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { AddToCase, Defanged, FindingRow, Notes } from "@/components/bits";
import { BarList } from "@/components/charts";
import { PageHeader } from "@/components/shell";
import { useSession } from "@/components/session";
import { Badge, Button, Card, CardHeader, CopyButton, Empty, ErrorNote, Spinner, useAction } from "@/components/ui";
import { api, useApi, type FindingSummary } from "@/lib/api";
import { ago, day, ENTITY_LABELS, IOC_LABELS, titleCase, VERDICT_TONE } from "@/lib/format";

interface Detail {
  id: number; type: string; value: string; defanged: string; doc_count: number; first_seen: string; last_seen: string;
  findings: (FindingSummary & { context: string })[];
  entities: { id: number; type: string; name: string; shared: number }[];
  related_iocs: { id: number; type: string; value: string; shared: number }[];
}
interface Enrichment {
  tags: string[]; feeds: string[]; benign: boolean; enrichable: boolean; key_rejected?: { provider: string; label: string; message: string }[];
  results: { provider: string; label: string; fetched_at: string; ok: boolean; verdict: string; score: number | null; summary: Record<string, unknown>; error: string }[];
}
const WATCHABLE = new Set(["domain", "email", "ip", "cve", "hash", "crypto", "username"]);

/** Provider summaries are small flat records; show them as labelled values, never as markup. */
function SummaryValue({ value }: { value: unknown }) {
  if (Array.isArray(value)) return <span className="break-words">{value.length === 0 ? "none" : value.slice(0, 24).join(", ")}{value.length > 24 ? ` and ${value.length - 24} more` : ""}</span>;
  if (value !== null && typeof value === "object") return <span className="break-words">{Object.entries(value as Record<string, unknown>).map(([k, v]) => `${k}: ${String(v)}`).join(", ")}</span>;
  return <span className="break-words">{String(value)}</span>;
}

export default function IndicatorPage() {
  const { id } = useParams<{ id: string }>();
  const { canWrite } = useSession();
  const { data: i, error } = useApi<Detail>(`/iocs/${id}`);
  const { data: enr, mutate: reloadEnrichment } = useApi<Enrichment>(`/iocs/${id}/enrichment`);
  const { busy, run } = useAction();
  const enrich = () => run(() => api(`/iocs/${id}/enrich`, { method: "POST" }), "Asking the configured providers. Results appear here shortly.").then(() => { setTimeout(() => reloadEnrichment(), 6000); setTimeout(() => reloadEnrichment(), 20000); });
  const setBenign = (benign: boolean) => run(() => api(`/iocs/${id}`, { method: "PATCH", body: { benign } }), benign ? "Marked benign: it no longer links findings together" : "Benign mark removed").then(() => reloadEnrichment());
  if (error) return <ErrorNote error={error} />;
  if (!i) return <Spinner />;

  return (
    <>
      <Link href="/indicators" className="mb-3 inline-flex items-center gap-1 text-xs text-muted hover:text-ink"><ArrowLeft className="h-3.5 w-3.5" /> All indicators</Link>
      <PageHeader
        title={<span className="flex items-center gap-2 break-all font-mono text-lg">{i.defanged}<CopyButton value={i.value} label="Copy original value" /></span>}
        subtitle={<span className="flex flex-wrap items-center gap-2 pt-1"><Badge tone="accent">{IOC_LABELS[i.type] ?? i.type}</Badge>
          {enr?.benign && <Badge tone="good" title="An analyst marked this as a common, harmless value. It is kept but no longer drives correlation."><ShieldOff className="h-3 w-3" />Benign</Badge>}
          {enr?.feeds.map((f) => <Badge key={f} tone="serious" title="Listed by this threat feed"><Radio className="h-3 w-3" />{f}</Badge>)}
          <span>{i.doc_count} finding{i.doc_count === 1 ? "" : "s"} · first seen {day(i.first_seen)} · last seen {ago(i.last_seen)}</span></span>}
        actions={<>
          <Link href={`/search?q=${encodeURIComponent(i.value)}`}><Button>Search findings</Button></Link>
          {i.type === "cve" && <Link href={`/vulnerabilities/${i.value}`}><Button>Vulnerability details</Button></Link>}
          {i.type === "crypto" && <Link href={`/crypto?address=${encodeURIComponent(i.value)}`}><Button><Coins className="h-3.5 w-3.5" /> Trace wallet</Button></Link>}
          {canWrite && WATCHABLE.has(i.type) && <Link href={`/watchlists?value=${encodeURIComponent(i.value)}`}><Button><Crosshair className="h-3.5 w-3.5" /> Watch</Button></Link>}
          <Link href={`/graph?node=ioc:${i.id}`}><Button><Share2 className="h-3.5 w-3.5" /> Relationships</Button></Link>
          <AddToCase objectType="ioc" objectId={String(i.id)} />
          {canWrite && enr && <Button title={enr.benign ? "Treat this as a threat indicator again" : "A shared service or other harmless value: stop it linking unrelated findings"} onClick={() => setBenign(!enr.benign)}><ShieldOff className="h-3.5 w-3.5" /> {enr.benign ? "Not benign" : "Mark benign"}</Button>}
        </>}
      />
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_22rem]">
        <div className="min-w-0 space-y-4">
          <Card>
            <CardHeader title="Where it appears" hint="The surrounding text is shown as captured, with secrets redacted" />
            {i.findings.length === 0 ? <Empty title="No findings" /> : i.findings.map((f) => (
              <FindingRow key={f.id} f={f} extra={f.context && <p className="mt-1.5 line-clamp-2 break-words rounded bg-sunken px-2 py-1 font-mono text-xs text-ink-2">{f.context}</p>} />
            ))}
          </Card>
          <Card><CardHeader title="Analyst notes" /><div className="px-4 py-3"><Notes objectType="ioc" objectId={String(i.id)} /></div></Card>
        </div>
        <aside className="min-w-0 space-y-4">
          {enr && (enr.enrichable || enr.results.length > 0) && (
            <Card>
              <CardHeader title="External context" hint="What reputation and scan-data services say about it" action={canWrite && enr.enrichable && <Button size="sm" busy={busy} onClick={enrich}><RefreshCw className="h-3.5 w-3.5" /> {enr.results.length ? "Refresh" : "Look up"}</Button>} />
{(enr.key_rejected ?? []).length > 0 && <p className="border-t border-line px-4 py-2 text-xs text-warning">{(enr.key_rejected ?? []).map((k) => k.label).join(", ")} skipped: {(enr.key_rejected ?? []).length === 1 ? "its key was" : "their keys were"} rejected. <Link href="/integrations" className="underline">Replace under Integrations</Link>; the free providers still answer.</p>}
              {enr.results.length === 0 ? <p className="px-4 py-3 text-sm text-muted">Not looked up yet. A lookup asks the configured providers about this value; the indicator itself is never contacted.</p> : (
                <ul className="divide-y divide-line">
                  {enr.results.map((r) => (
                    <li key={r.provider} className="px-4 py-2.5">
                      <div className="flex items-center justify-between gap-2 text-sm font-medium"><span>{r.label}</span>{r.ok ? <Badge tone={VERDICT_TONE[r.verdict] ?? "neutral"}>{titleCase(r.verdict || "unknown")}{r.score !== null ? ` · ${r.score}` : ""}</Badge> : <Badge tone="warning">Lookup failed</Badge>}</div>
                      {r.ok ? (
                        <dl className="mt-1 space-y-0.5 text-xs">
                          {Object.entries(r.summary ?? {}).filter(([, v]) => v !== null && v !== "" && !(Array.isArray(v) && v.length === 0)).slice(0, 10).map(([k, v]) => <div key={k} className="flex gap-2"><dt className="w-24 shrink-0 text-muted">{titleCase(k)}</dt><dd className="min-w-0 flex-1 text-ink-2"><SummaryValue value={v} /></dd></div>)}
                        </dl>
                      ) : <p className="mt-1 text-xs text-muted">{r.error}</p>}
                      <p className="mt-1 text-2xs text-muted">Checked {ago(r.fetched_at)}</p>
                    </li>
                  ))}
                </ul>
              )}
              {enr.tags.length > 0 && <div className="flex flex-wrap gap-1 border-t border-line px-4 py-2">{enr.tags.map((t) => <Badge key={t}>{t}</Badge>)}</div>}
              <p className="border-t border-line px-4 py-2 text-xs text-muted"><Link className="link" href="/integrations">Providers and API keys</Link></p>
            </Card>
          )}
          {i.entities.length > 0 && (
            <Card>
              <CardHeader title="Associated with" hint="Entities in the same findings" />
              <div className="p-3"><BarList items={i.entities.filter((e) => e.type !== "incident").map((e) => ({ key: String(e.id), label: e.name, value: e.shared, href: `/entities/${e.id}`, hint: ENTITY_LABELS[e.type] }))} /></div>
            </Card>
          )}
          {i.related_iocs.length > 0 && (
            <Card>
              <CardHeader title="Seen together with" />
              <ul className="divide-y divide-line">
                {i.related_iocs.slice(0, 15).map((r) => (
                  <li key={r.id} className="flex items-center justify-between gap-2 px-4 py-2">
                    <div className="min-w-0"><div className="text-2xs text-muted">{IOC_LABELS[r.type] ?? r.type}</div><Defanged value={r.value} /></div>
                    <Link href={`/indicators/${r.id}`} className="link shrink-0 text-xs">{r.shared}×</Link>
                  </li>
                ))}
              </ul>
            </Card>
          )}
        </aside>
      </div>
    </>
  );
}

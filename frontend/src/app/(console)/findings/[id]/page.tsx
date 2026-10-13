"use client";

import { AlertTriangle, ArrowLeft, BadgeCheck, CheckCircle2, Download, FileSearch, History, KeyRound, RefreshCw, Share2, ShieldAlert, Sparkles, X } from "lucide-react";
import Link from "next/link";
import { useParams, useSearchParams } from "next/navigation";
import { useMemo, useState } from "react";
import { AddToCase, AiLabel, CrawlButton, CredentialBadge, Defanged, NetworkBadge, Notes, PreserveEvidence, RiskMeter, SeverityBadge, StateBadge, useAiJob, VerificationBadge } from "@/components/bits";
import { PageHeader } from "@/components/shell";
import { useSession } from "@/components/session";
import { Badge, Button, Card, CardHeader, CopyButton, Empty, ErrorNote, Modal, Spinner, Tabs, useAction } from "@/components/ui";
import { api, useApi, type FindingSummary, type SourceBrief } from "@/lib/api";
import { ago, cn, defang, ENTITY_LABELS, EXPOSURE_LABELS, IOC_LABELS, secretLabel, stamp, titleCase } from "@/lib/format";

interface Version { version: number; captured_at: string; content_sha256: string; raw_sha256: string; chain_hash: string; http_status: number | null; bytes: number; change: { added_lines?: number; removed_lines?: number; similarity?: number; new_indicators?: string[]; removed_indicators?: string[] } }
interface Detail extends FindingSummary {
  content: string; threat_types: string[]; sectors: string[]; country_names: Record<string, string>; risk_factors: { factor: string; points: number }[];
  exposure: Record<string, number>; meta: Record<string, unknown>; last_changed: string; content_sha256: string; raw_sha256: string;
  source: { id: number; name: string; category: string; trust: number; network: string; connector: string };
  tags: string[];
  iocs: { id: number; type: string; value: string; doc_count: number; count: number; context: string }[];
  entities: { id: number; type: string; name: string; doc_count: number; role: string; confidence: number }[];
  versions: Version[];
  alerts: { id: number; category: string; severity: string; status: string; matched: string; created_at: string; watchlist: string }[];
  cases: { id: number; title: string; status: string }[];
  duplicate_of: FindingSummary | null; duplicates: FindingSummary[];
  related: (FindingSummary & { reason: string })[];
  verification: string; verification_label: string; corroboration: number; admiralty: string; reliability_label: string;
  techniques: { id: string; name: string; tactics: string[] }[];
  exposures: { id: number; kind: string; identity: string; domain: string; service: string; secret_type: string; fingerprint: string; password_exposed: boolean; status: string }[];
  ai_summary: AiSummary | null;
}
interface AiSummary { summary: string; key_points: string[]; recommended_actions: string[] }
interface Observations {
  status: "online" | "missing" | "removed" | "source_offline" | "unreachable" | "feed"; detail: string; first_seen: string; last_seen: string; last_changed: string;
  days: { date: string; fetches: number; ok: number; http_status: number | null; changed: boolean }[]; source: SourceBrief;
}
const PAGE_STATUS: Record<Observations["status"], { label: string; tone: "good" | "warning" | "critical" | "neutral" }> = {
  online: { label: "Online", tone: "good" }, missing: { label: "No longer on the site", tone: "warning" }, removed: { label: "Removed", tone: "critical" },
  source_offline: { label: "Source offline", tone: "critical" }, unreachable: { label: "Last fetch failed", tone: "warning" }, feed: { label: "Feed entry", tone: "neutral" },
};
const TABS = ["content", "iocs", "exposures", "history", "evidence", "notes"] as const;
interface Evidence { intact: boolean; method: string; captures: { version: number; captured_at: string; url: string; http_status: number | null; bytes: number; raw_sha256: string; content_sha256: string; prev_chain_hash: string; chain_hash: string; hmac_sha256: string; verified: boolean }[] }
interface Diff { lines: { kind: "add" | "del" | "ctx" | "hunk"; text: string }[] }

/** Render stored text with indicators marked. Content is plain text: nothing here is ever a link. */
function Content({ text, terms }: { text: string; terms: string[] }) {
  const parts = useMemo(() => {
    const usable = terms.filter((t) => t.length >= 4).sort((a, b) => b.length - a.length).slice(0, 150);
    if (!usable.length) return [text];
    const pattern = new RegExp(`(${usable.map((t) => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})`, "gi");
    return text.split(pattern);
  }, [text, terms]);
  const lookup = useMemo(() => new Set(terms.map((t) => t.toLowerCase())), [terms]);
  return (
    <pre className="scroll-thin max-h-[640px] overflow-auto whitespace-pre-wrap break-words px-4 py-3 font-sans text-sm leading-relaxed text-ink-2">
      {parts.map((p, i) => (lookup.has(p.toLowerCase()) ? <mark key={i}>{p}</mark> : p))}
    </pre>
  );
}

function Hash({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center gap-2 py-1">
      <span className="w-28 shrink-0 text-xs text-muted">{label}</span>
      <code className="min-w-0 flex-1 truncate font-mono text-xs" title={value}>{value || "n/a"}</code>
      {value && <CopyButton value={value} />}
    </div>
  );
}

export default function FindingPage() {
  const { id } = useParams<{ id: string }>();
  const { meta, canWrite } = useSession();
  const { data: f, error, mutate } = useApi<Detail>(`/findings/${id}`);
  const wanted = useSearchParams().get("tab");
  const [tab, setTab] = useState<(typeof TABS)[number]>((TABS as readonly string[]).includes(wanted ?? "") ? (wanted as (typeof TABS)[number]) : "content");
  const { data: seen } = useApi<Observations>(tab === "history" ? `/findings/${id}/observations` : null);
  const { data: ai } = useApi<{ enabled: boolean; model: string }>("/ai/status");
  const summary = useAiJob();
  const [diffPair, setDiffPair] = useState<[number, number] | null>(null);
  const [iocFilter, setIocFilter] = useState("");
  const [tagDraft, setTagDraft] = useState("");
  const { data: evidence } = useApi<Evidence>(tab === "evidence" ? `/findings/${id}/evidence` : null);
  const { data: diff } = useApi<Diff>(diffPair ? `/findings/${id}/diff?a=${diffPair[0]}&b=${diffPair[1]}` : null);
  const { run } = useAction();

  if (error) return <ErrorNote error={error} />;
  if (!f) return <Spinner />;

  const patch = (body: Record<string, unknown>, message: string) => run(() => api(`/findings/${id}`, { method: "PATCH", body }), message).then(() => mutate());
  const iocTypes = Array.from(new Set(f.iocs.map((i) => i.type)));
  // A freshly generated summary is shown straight away; a stored one comes with the finding.
  const aiSummary: AiSummary | null = summary.job.status === "done" && summary.job.summary ? { summary: summary.job.summary, key_points: summary.job.key_points ?? [], recommended_actions: summary.job.recommended_actions ?? [] } : f.ai_summary;
  const shownIocs = f.iocs.filter((i) => !iocFilter || i.type === iocFilter);
  const exposures = Object.entries(f.exposure ?? {}).filter(([, n]) => n > 0);
  const downloadEvidence = () => {
    const blob = new Blob([JSON.stringify(evidence, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `evidence-${id}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  return (
    <>
      <Link href="/search" className="mb-3 inline-flex items-center gap-1 text-xs text-muted hover:text-ink"><ArrowLeft className="h-3.5 w-3.5" /> Back to search</Link>
      <PageHeader
        title={<span className="break-words">{f.title}</span>}
        subtitle={<span className="flex flex-wrap items-center gap-1.5 pt-1">
          <SeverityBadge severity={f.severity} /><Badge tone="accent">{f.threat_label}</Badge><NetworkBadge network={f.network} />
          <VerificationBadge state={f.verification} admiralty={f.admiralty} corroboration={f.corroboration} />
          {f.has_credentials && <CredentialBadge count={f.exposure?.credential_pairs} />}
          {f.version_count > 1 && <Badge><History className="h-3 w-3" />{f.version_count} versions</Badge>}
          <span className="text-xs">First seen {stamp(f.first_seen)} · {ago(f.first_seen)}</span>
        </span>}
        actions={<>
          {canWrite && (
            <select aria-label="Triage status" className="field h-9 w-36" value={f.status} onChange={(e) => patch({ status: e.target.value }, "Status updated")}>
              {meta.finding_statuses.map((s) => <option key={s} value={s}>{titleCase(s)}</option>)}
            </select>
          )}
          {canWrite && (f.verification === "confirmed"
            ? <Button title="Return to the automatic verification state" onClick={() => patch({ confirmed: false }, "Confirmation removed")}><BadgeCheck className="h-3.5 w-3.5" /> Confirmed</Button>
            : <Button title="Mark as confirmed by an analyst. This raises its credibility grade." onClick={() => patch({ confirmed: true }, "Marked as confirmed")}><BadgeCheck className="h-3.5 w-3.5" /> Confirm</Button>)}
          <Link href={`/search?q=${encodeURIComponent(`similar:${f.id}`)}`}><Button title="Other findings with similar wording">Similar</Button></Link>
          <Link href={`/graph?node=finding:${f.id}`}><Button><Share2 className="h-3.5 w-3.5" /> Connections</Button></Link>
          {f.network === "onion" && <CrawlButton url={f.url} label="Crawl" size="md" />}
          <PreserveEvidence findingId={f.id} />
          <AddToCase objectType="finding" objectId={f.id} label="Add to investigation" />
        </>}
      />

      {f.duplicate_of && (
        <div className="mb-4 flex items-start gap-2 rounded-md border border-line bg-warning-soft px-3 py-2 text-sm">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warning" />
          <span>This is a duplicate of <Link className="link font-medium" href={`/findings/${f.duplicate_of.id}`}>{f.duplicate_of.title}</Link> from {f.duplicate_of.source_name}. Alerts are raised on the original only.</span>
        </div>
      )}

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_22rem]">
        <div className="min-w-0">
          <Card>
            <div className="px-3 pt-1">
              <Tabs value={tab} onChange={setTab} tabs={[
                { id: "content", label: "Content" }, { id: "iocs", label: "Indicators", count: f.iocs.length },
                ...(f.exposures.length ? [{ id: "exposures" as const, label: "Exposed accounts", count: f.exposures.length }] : []),
                { id: "history", label: "History", count: f.versions.length }, { id: "evidence", label: "Evidence" }, { id: "notes", label: "Notes" },
              ]} />
            </div>

            {tab === "content" && (
              <>
                {meta.redaction && exposures.length > 0 && (
                  <div className="flex items-start gap-2 border-b border-line bg-critical-soft px-4 py-2.5 text-sm">
                    <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-critical" />
                    <span>This capture contained {exposures.map(([k, n]) => `${n.toLocaleString()} ${k.replace(/_/g, " ").replace(/s$/, n === 1 ? "" : "s")}`).join(", ")}. Secrets were redacted before storage; the hash of the original capture is preserved as evidence.</span>
                  </div>
                )}
                <Content text={f.content} terms={f.iocs.filter((i) => i.type !== "url").map((i) => i.value)} />
              </>
            )}

            {tab === "iocs" && (
              f.iocs.length === 0 ? <Empty title="No indicators extracted" /> : (
                <div>
                  <div className="flex flex-wrap gap-1.5 border-b border-line px-4 py-2.5">
                    <button onClick={() => setIocFilter("")} className={cn("rounded px-2 py-0.5 text-xs", !iocFilter ? "bg-accent-soft text-accent-ink" : "text-ink-2 hover:bg-sunken")}>All {f.iocs.length}</button>
                    {iocTypes.map((t) => (
                      <button key={t} onClick={() => setIocFilter(t)} className={cn("rounded px-2 py-0.5 text-xs", iocFilter === t ? "bg-accent-soft text-accent-ink" : "text-ink-2 hover:bg-sunken")}>{IOC_LABELS[t] ?? t} {f.iocs.filter((i) => i.type === t).length}</button>
                    ))}
                  </div>
                  <div className="scroll-thin max-h-[600px] overflow-auto">
                    <table className="w-full">
                      <thead className="sticky top-0 bg-surface"><tr><th className="th">Type</th><th className="th">Value</th><th className="th">Context</th><th className="th text-right">Seen in</th></tr></thead>
                      <tbody className="divide-y divide-line">
                        {shownIocs.map((i) => (
                          <tr key={i.id}>
                            <td className="td whitespace-nowrap text-xs text-muted">{IOC_LABELS[i.type] ?? i.type}</td>
                            <td className="td max-w-xs"><Defanged value={i.value} pivot /></td>
                            <td className="td max-w-md text-xs text-muted"><span className="line-clamp-2 break-words">{i.context}</span></td>
                            <td className="td whitespace-nowrap text-right"><Link className="link text-xs" href={`/indicators/${i.id}`}>{i.doc_count} finding{i.doc_count === 1 ? "" : "s"}</Link></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )
            )}

            {tab === "exposures" && (
              <div>
                <p className="border-b border-line px-4 py-2.5 text-xs text-muted">Who and what this capture exposes. Passwords and secrets were discarded; a fingerprint is kept so the same secret can be recognised in another leak. <Link className="link" href="/exposures">Open identity exposure</Link> to track remediation.</p>
                <div className="scroll-thin max-h-[600px] overflow-auto">
                  <table className="w-full">
                    <thead className="sticky top-0 bg-surface"><tr><th className="th">Account or secret</th><th className="th">Kind</th><th className="th">Where it works</th><th className="th">Status</th></tr></thead>
                    <tbody className="divide-y divide-line">
                      {f.exposures.map((x) => (
                        <tr key={x.id}>
                          <td className="td max-w-xs">{x.identity ? <Defanged value={x.identity} /> : <span className="text-xs text-muted">{secretLabel(x.secret_type)}</span>}
                            <div className="mt-0.5 flex flex-wrap items-center gap-1">{x.password_exposed && <Badge tone="critical"><KeyRound className="h-3 w-3" />Password exposed</Badge>}{x.fingerprint && <span className="font-mono text-2xs text-muted">fp {x.fingerprint}</span>}</div></td>
                          <td className="td whitespace-nowrap text-xs text-ink-2">{EXPOSURE_LABELS[x.kind] ?? titleCase(x.kind)}</td>
                          <td className="td max-w-[14rem] truncate font-mono text-xs">{defang(x.service || x.domain) || <span className="font-sans text-muted">Unknown</span>}</td>
                          <td className="td"><Badge tone={x.status === "open" ? "warning" : x.status === "remediated" ? "good" : "neutral"}>{titleCase(x.status)}</Badge></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {tab === "history" && seen && (
              <div className="border-b border-line px-4 py-3">
                <div className="flex flex-wrap items-center gap-2 text-sm"><Badge tone={PAGE_STATUS[seen.status].tone}>{PAGE_STATUS[seen.status].label}</Badge><span className="text-ink-2">{seen.detail}.</span></div>
                <dl className="mt-2 grid gap-3 text-sm sm:grid-cols-3">
                  <div><dt className="label">First seen</dt><dd>{stamp(seen.first_seen)}</dd></div>
                  <div><dt className="label">Last seen</dt><dd>{stamp(seen.last_seen)}</dd></div>
                  <div><dt className="label">Last changed</dt><dd>{stamp(seen.last_changed)}</dd></div>
                </dl>
                {seen.days.length > 0 && (
                  <div className="mt-3">
                    <div className="label mb-1">Observed</div>
                    <div className="flex flex-wrap gap-1">
                      {seen.days.map((d) => (
                        <span key={d.date} title={`${stamp(d.date).slice(0, 11)}: fetched ${d.fetches} time${d.fetches === 1 ? "" : "s"}, ${d.ok} read${d.changed ? ", content changed" : ""}${d.http_status ? `, HTTP ${d.http_status}` : ""}`}
                          className={cn("rounded px-1.5 py-0.5 text-2xs font-medium tabular-nums", d.ok === 0 ? "bg-critical-soft text-critical" : d.changed ? "bg-warning-soft text-warning" : "bg-good-soft text-good")}>
                          {new Date(d.date).toLocaleDateString("en-GB", { day: "2-digit", month: "short" })}{d.changed ? " · changed" : d.ok === 0 ? " · failed" : ""}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                <p className="mt-2 text-xs text-muted">Source: <Link className="link" href={`/sources/${seen.source.id}`}>{seen.source.title || seen.source.name}</Link> <StateBadge state={seen.source.state} />. Every version below stays searchable even if the page is gone.</p>
              </div>
            )}
            {tab === "history" && (
              <ol className="divide-y divide-line">
                {f.versions.map((v, idx) => {
                  const previous = f.versions[idx + 1];
                  return (
                    <li key={v.version} className="px-4 py-3">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="text-sm font-medium">Version {v.version} <span className="font-normal text-muted">· captured {stamp(v.captured_at)}</span></div>
                        {previous && <Button size="sm" onClick={() => setDiffPair([previous.version, v.version])}><FileSearch className="h-3.5 w-3.5" /> Compare with v{previous.version}</Button>}
                      </div>
                      {v.version === 1 ? <p className="mt-1 text-xs text-muted">First capture.</p> : (
                        <div className="mt-1 text-xs text-ink-2">
                          <span className="text-good">+{v.change.added_lines ?? 0} lines</span> · <span className="text-critical">−{v.change.removed_lines ?? 0} lines</span> · {Math.round((v.change.similarity ?? 0) * 100)}% unchanged
                          {(v.change.new_indicators?.length ?? 0) > 0 && <div className="mt-1 break-words text-muted">New indicators: {v.change.new_indicators!.slice(0, 8).map((x) => defang(x.replace(/^[a-z]+:/, ""))).join(", ")}{v.change.new_indicators!.length > 8 ? "…" : ""}</div>}
                        </div>
                      )}
                    </li>
                  );
                })}
              </ol>
            )}

            {tab === "evidence" && (
              !evidence ? <Spinner label="Verifying evidence chain" /> : (
                <div className="px-4 py-3">
                  <div className={cn("mb-3 flex items-start gap-2 rounded-md px-3 py-2 text-sm", evidence.intact ? "bg-good-soft" : "bg-critical-soft")}>
                    {evidence.intact ? <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-good" /> : <X className="mt-0.5 h-4 w-4 shrink-0 text-critical" />}
                    <span>{evidence.intact ? `Evidence chain verified: ${evidence.captures.length} capture${evidence.captures.length === 1 ? "" : "s"}, every hash and signature checks out.` : "Verification failed. A stored capture does not match its recorded hash or signature."}</span>
                  </div>
                  <p className="mb-3 text-xs text-muted">{evidence.method}</p>
                  {evidence.captures.map((c) => (
                    <div key={c.version} className="mb-3 rounded-md border border-line px-3 py-2">
                      <div className="mb-1 flex items-center justify-between text-sm font-medium">
                        <span>Capture {c.version} · {stamp(c.captured_at)}</span>
                        <Badge tone={c.verified ? "good" : "critical"}>{c.verified ? "Verified" : "Mismatch"}</Badge>
                      </div>
                      <div className="mb-1 flex items-center gap-2 py-1"><span className="w-28 shrink-0 text-xs text-muted">Source URL</span><Defanged value={c.url} className="flex-1" /></div>
                      <Hash label="Raw SHA-256" value={c.raw_sha256} />
                      <Hash label="Content SHA-256" value={c.content_sha256} />
                      <Hash label="Chain hash" value={c.chain_hash} />
                      <Hash label="HMAC-SHA-256" value={c.hmac_sha256} />
                    </div>
                  ))}
                  <Button size="sm" onClick={downloadEvidence}><Download className="h-3.5 w-3.5" /> Download evidence record (JSON)</Button>
                </div>
              )
            )}

            {tab === "notes" && <div className="px-4 py-3"><Notes objectType="finding" objectId={f.id} /></div>}
          </Card>

          {f.related.length > 0 && (
            <Card className="mt-4">
              <CardHeader title="Related findings" hint="Same victim or incident, a shared indicator, or similar wording" />
              <ul className="divide-y divide-line">
                {f.related.map((r) => (
                  <li key={r.id} className="flex items-center gap-3 px-4 py-2.5">
                    <SeverityBadge severity={r.severity} />
                    <div className="min-w-0 flex-1">
                      <Link href={`/findings/${r.id}`} className="block truncate text-sm hover:underline">{r.title}</Link>
                      <div className="truncate text-xs text-muted">{r.reason} · {r.source_name} · {ago(r.first_seen)}</div>
                    </div>
                  </li>
                ))}
              </ul>
            </Card>
          )}
        </div>

        <aside className="min-w-0 space-y-4">
          {(aiSummary || ai?.enabled) && (
            <Card>
              <CardHeader title={<span className="inline-flex items-center gap-1.5"><Sparkles className="h-3.5 w-3.5 text-accent-ink" />Analyst summary</span>}
                action={ai?.enabled && aiSummary && <Button size="sm" variant="ghost" busy={summary.busy} title="Generate again" onClick={() => summary.start("/ai/summarize", { finding_id: f.id, refresh: true })}><RefreshCw className="h-3.5 w-3.5" /></Button>} />
              {aiSummary ? (
                <div className="space-y-2 px-4 py-3 text-sm">
                  <p className="leading-relaxed text-ink-2">{aiSummary.summary}</p>
                  {aiSummary.key_points.length > 0 && <ul className="list-disc space-y-1 pl-4 text-ink-2">{aiSummary.key_points.map((k, i) => <li key={i}>{k}</li>)}</ul>}
                  {aiSummary.recommended_actions.length > 0 && <div><div className="label mb-1">What a defender should check</div><ul className="list-disc space-y-1 pl-4 text-ink-2">{aiSummary.recommended_actions.map((k, i) => <li key={i}>{k}</li>)}</ul></div>}
                  <p className="border-t border-line pt-2"><AiLabel>AI-drafted from this capture only. Verify against the content.</AiLabel></p>
                </div>
              ) : (
                <div className="px-4 py-3 text-sm">
                  {summary.job.status === "error" ? <p className="mb-2 text-critical">{summary.job.error}</p> : <p className="mb-2 text-muted">Summarise what this capture says, who is affected and what to check. The capture text is sent to the model; nothing else is.</p>}
                  <Button size="sm" busy={summary.busy} onClick={() => summary.start("/ai/summarize", { finding_id: f.id })}><Sparkles className="h-3.5 w-3.5" /> {summary.busy ? "Summarising" : "Summarise"}</Button>
                </div>
              )}
            </Card>
          )}

          <Card>
            <CardHeader title="Risk" action={<RiskMeter score={f.risk_score} />} />
            <ul className="px-4 py-2 text-sm">
              {f.risk_factors.map((r, i) => (
                <li key={i} className="flex items-baseline justify-between gap-3 py-1">
                  <span className="text-ink-2">{r.factor}</span>
                  <span className={cn("shrink-0 tabular-nums", r.points < 0 ? "text-good" : "text-ink")}>{r.points > 0 ? "+" : ""}{r.points}</span>
                </li>
              ))}
              <li className="mt-1 flex justify-between border-t border-line pt-2 font-semibold"><span>Score</span><span className="tabular-nums">{f.risk_score} / 100</span></li>
            </ul>
            <p className="border-t border-line px-4 py-2 text-xs text-muted">Classification confidence {f.confidence}%{f.threat_types.length > 1 ? ` · also ${f.threat_types.slice(1).map((t) => (meta.threat_types[t] ?? t).toLowerCase()).join(", ")}` : ""}</p>
          </Card>

          <Card>
            <CardHeader title="Details" />
            <dl className="space-y-2 px-4 py-3 text-sm">
              <div><dt className="label">Source</dt><dd className="mt-0.5"><Link className="link" href={`/sources/${f.source.id}`}>{f.source.name}</Link> <span className="text-xs text-muted">· {titleCase(f.source.category)} · trust {f.source.trust}</span></dd></div>
              <div><dt className="label">Reliability and verification</dt><dd className="mt-0.5 text-ink-2">{f.verification_label}{f.corroboration > 0 ? `, corroborated by ${f.corroboration} other source${f.corroboration === 1 ? "" : "s"}` : ""}. <span className="text-xs text-muted">Admiralty grade <span className="font-mono">{f.admiralty}</span>: source {f.reliability_label.toLowerCase()}.</span></dd></div>
              <div><dt className="label">Location</dt><dd className="mt-0.5"><Defanged value={f.url} /></dd></div>
              {f.countries.length > 0 && <div><dt className="label">Countries</dt><dd className="mt-0.5 flex flex-wrap gap-1">{f.countries.map((c) => <Link key={c} href={`/search?country=${c}`}><Badge>{f.country_names[c] ?? c}</Badge></Link>)}</dd></div>}
              {f.sectors.length > 0 && <div><dt className="label">Sector</dt><dd className="mt-0.5">{f.sectors.join(", ")}</dd></div>}
              {f.published_at && <div><dt className="label">Reported by source</dt><dd className="mt-0.5">{stamp(f.published_at)}</dd></div>}
              <div><dt className="label">Last seen</dt><dd className="mt-0.5">{stamp(f.last_seen)}</dd></div>
              <div><dt className="label">Tags</dt>
                <dd className="mt-1 flex flex-wrap items-center gap-1">
                  {f.tags.map((t) => (
                    <Badge key={t}>#{t}{canWrite && <button aria-label={`Remove tag ${t}`} onClick={() => patch({ tags: f.tags.filter((x) => x !== t) }, "Tag removed")}><X className="h-3 w-3" /></button>}</Badge>
                  ))}
                  {canWrite && (
                    <form onSubmit={(e) => { e.preventDefault(); if (tagDraft.trim()) { patch({ tags: [...f.tags, tagDraft] }, "Tag added"); setTagDraft(""); } }}>
                      <input value={tagDraft} onChange={(e) => setTagDraft(e.target.value)} placeholder="Add tag" aria-label="Add tag" className="field h-6 w-24 px-1.5 text-xs" />
                    </form>
                  )}
                  {!canWrite && f.tags.length === 0 && <span className="text-muted">None</span>}
                </dd>
              </div>
            </dl>
          </Card>

          {f.techniques.length > 0 && (
            <Card>
              <CardHeader title="ATT&CK techniques" hint="Named in the text or matched from described behaviour" />
              <ul className="divide-y divide-line">
                {f.techniques.map((t) => (
                  <li key={t.id} className="flex items-center justify-between gap-2 px-4 py-2 text-sm">
                    <Link href={`/attack/${t.id}`} className="min-w-0 truncate hover:underline"><span className="font-mono text-xs text-muted">{t.id}</span> {t.name}</Link>
                    <span className="shrink-0 text-xs text-muted">{t.tactics.slice(0, 1).map((x) => meta.tactics?.find((m) => m.shortname === x)?.name ?? x).join("")}</span>
                  </li>
                ))}
              </ul>
            </Card>
          )}

          {f.entities.filter((e) => e.type !== "technique").length > 0 && (
            <Card>
              <CardHeader title="Actors and organisations" />
              <ul className="divide-y divide-line">
                {f.entities.filter((e) => e.type !== "technique").map((e) => (
                  <li key={e.id} className="flex items-center justify-between gap-2 px-4 py-2 text-sm">
                    <Link href={`/entities/${e.id}`} className="min-w-0 flex-1 truncate hover:underline">{e.name}</Link>
                    <span className="shrink-0 text-xs text-muted">{e.role === "victim" ? "Victim" : e.role === "actor" ? "Named actor" : ENTITY_LABELS[e.type]}</span>
                    <Link href={`/search?q=${encodeURIComponent(/\s/.test(e.name) ? `"${e.name}"` : e.name)}`} title="Search everywhere for this" className="shrink-0 text-xs text-muted hover:text-accent-ink">search</Link>
                    <Link href={`/graph?node=entity:${e.id}`} title="Find connections" className="shrink-0 text-xs text-muted hover:text-accent-ink">connections</Link>
                  </li>
                ))}
              </ul>
            </Card>
          )}

          {(f.alerts.length > 0 || f.cases.length > 0) && (
            <Card>
              <CardHeader title="Linked work" />
              <ul className="divide-y divide-line text-sm">
                {f.alerts.map((a) => (
                  <li key={`a${a.id}`} className="px-4 py-2"><div className="flex items-center gap-2"><SeverityBadge severity={a.severity} /><span className="truncate">{a.matched}</span></div><div className="mt-0.5 text-xs text-muted">Alert · {a.watchlist} · {titleCase(a.status)}</div></li>
                ))}
                {f.cases.map((c) => <li key={`c${c.id}`} className="px-4 py-2"><Link className="link" href={`/cases/${c.id}`}>{c.title}</Link><div className="text-xs text-muted">Case · {titleCase(c.status)}</div></li>)}
              </ul>
            </Card>
          )}

          {f.duplicates.length > 0 && (
            <Card>
              <CardHeader title={`Also seen at (${f.duplicates.length})`} hint="Duplicate captures from other sources" />
              <ul className="divide-y divide-line text-sm">{f.duplicates.map((d) => <li key={d.id} className="px-4 py-2"><Link className="link" href={`/findings/${d.id}`}>{d.source_name}</Link><div className="text-xs text-muted">{stamp(d.first_seen)}</div></li>)}</ul>
            </Card>
          )}
        </aside>
      </div>

      <Modal open={Boolean(diffPair)} onClose={() => setDiffPair(null)} title={diffPair ? `Changes from version ${diffPair[0]} to ${diffPair[1]}` : ""} wide>
        {!diff ? <Spinner /> : diff.lines.length === 0 ? <p className="text-sm text-muted">No textual differences.</p> : (
          <pre className="scroll-thin max-h-[60vh] overflow-auto rounded-md border border-line text-xs leading-relaxed">
            {diff.lines.map((l, i) => (
              <div key={i} className={cn("whitespace-pre-wrap break-words px-3 py-0.5 font-mono", l.kind === "add" && "bg-good-soft", l.kind === "del" && "bg-critical-soft", l.kind === "hunk" && "bg-sunken text-muted")}>
                <span className="mr-2 select-none text-muted">{l.kind === "add" ? "+" : l.kind === "del" ? "−" : " "}</span>{l.text}
              </div>
            ))}
          </pre>
        )}
      </Modal>
    </>
  );
}

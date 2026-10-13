"use client";

import { BadgeCheck, CircleAlert, CircleCheck, CircleDashed, CircleDot, CircleHelp, CircleX, FolderPlus, Globe, Info, KeyRound, OctagonAlert, Play, Search, Sparkles, Trash2, TriangleAlert, Users } from "lucide-react";
import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import { api, useApi, type Factor, type FindingSummary, type Part } from "@/lib/api";
import { ago, cn, defang, stamp, titleCase } from "@/lib/format";
import { useSession } from "./session";
import { Badge, Button, CopyButton, Empty, Field, Modal, Spinner, useAction } from "./ui";

const SEVERITY = {
  critical: { tone: "critical", icon: OctagonAlert },
  high: { tone: "serious", icon: TriangleAlert },
  medium: { tone: "warning", icon: CircleAlert },
  low: { tone: "accent", icon: CircleDot },
  info: { tone: "neutral", icon: Info },
} as const;

/** Severity is always an icon plus a word; colour only reinforces it. */
export function SeverityBadge({ severity }: { severity: string }) {
  const meta = SEVERITY[severity as keyof typeof SEVERITY] ?? SEVERITY.info;
  return <Badge tone={meta.tone}><meta.icon className="h-3 w-3" />{titleCase(severity)}</Badge>;
}

export function RiskMeter({ score }: { score: number }) {
  const color = score >= 80 ? "var(--critical)" : score >= 60 ? "var(--serious)" : score >= 40 ? "var(--warning)" : "var(--accent)";
  return (
    <span className="inline-flex items-center gap-1.5" title={`Risk score ${score} of 100`}>
      <span className="h-1.5 w-10 overflow-hidden rounded-full bg-sunken"><span className="block h-full rounded-full" style={{ width: `${score}%`, background: color }} /></span>
      <span className="w-6 text-xs tabular-nums text-ink-2">{score}</span>
    </span>
  );
}

export function NetworkBadge({ network }: { network: string }) {
  return network === "onion"
    ? <Badge tone="neutral" title="Collected from a Tor hidden service"><span className="h-1.5 w-1.5 rounded-full bg-ink-2" />Tor</Badge>
    : <Badge tone="neutral" title="Collected from the surface web"><Globe className="h-3 w-3" />Web</Badge>;
}

export function CredentialBadge({ count }: { count?: number }) {
  return <Badge tone="critical" title="Passwords were present in this capture. They are redacted and never stored."><KeyRound className="h-3 w-3" />{count ? `${count.toLocaleString()} credentials` : "Credentials"}</Badge>;
}

export function Countries({ codes }: { codes: string[] }) {
  const { meta } = useSession();
  if (!codes?.length) return null;
  return <span className="text-xs text-ink-2">{codes.slice(0, 3).map((c) => meta.countries[c] ?? c).join(", ")}{codes.length > 3 ? ` +${codes.length - 3}` : ""}</span>;
}

/** Search highlights arrive as text parts, never HTML, so crawled content cannot inject markup. */
export function Highlight({ parts }: { parts: Part[] }) {
  return <>{parts.map((p, i) => (p.h ? <mark key={i}>{p.t}</mark> : <span key={i}>{p.t}</span>))}</>;
}

/** Indicators are shown defanged and are never links to the thing itself. The copy button copies the real value; the pivot searches for it. */
export function Defanged({ value, className, pivot }: { value: string; className?: string; pivot?: boolean }) {
  return (
    <span className={cn("inline-flex min-w-0 max-w-full items-center gap-1 align-bottom", className)}>
      <span className="truncate font-mono text-xs" title={defang(value)}>{defang(value)}</span>
      <CopyButton value={value} label="Copy original value" />
      {pivot && <Link href={`/search?q=${encodeURIComponent(value)}`} title="Search everywhere for this" aria-label="Search everywhere for this" className="inline-flex h-5 w-5 shrink-0 items-center justify-center rounded text-muted hover:bg-sunken hover:text-ink"><Search className="h-3 w-3" /></Link>}
    </span>
  );
}

const STATE = {
  online: { tone: "good", icon: CircleCheck, label: "Online" }, degraded: { tone: "warning", icon: TriangleAlert, label: "Degraded" },
  offline: { tone: "critical", icon: CircleX, label: "Offline" }, unknown: { tone: "neutral", icon: CircleHelp, label: "Unknown" },
} as const;

/** Whether a source answers. Icon and word, never colour alone. */
export function StateBadge({ state }: { state: string }) {
  const s = STATE[state as keyof typeof STATE] ?? STATE.unknown;
  return <Badge tone={s.tone}><s.icon className="h-3 w-3" />{s.label}</Badge>;
}

/** Start a research crawl from a URL: the dialog used everywhere a page or a site can be crawled. */
export function CrawlButton({ url, label = "Crawl", size = "sm", caseId }: { url?: string; label?: string; size?: "sm" | "md"; caseId?: number }) {
  const { canWrite } = useSession();
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ url: url ?? "", depth: 1, max_pages: 50, monitor: false });
  const { data: policy } = useApi<{ values: { research_max_depth: number; research_max_pages: number } }>(open ? "/settings/collection" : null);
  const { busy, run } = useAction();
  if (!canWrite) return null;
  const maxDepth = policy?.values.research_max_depth ?? 4;
  const maxPages = policy?.values.research_max_pages ?? 300;
  const start = () => run(async () => {
    const job = await api<{ id: number }>("/crawls", { method: "POST", body: { ...form, case_id: caseId ?? null } });
    window.location.href = `/crawls/${job.id}`;
  });
  return (
    <>
      <Button size={size} onClick={() => { setForm((f) => ({ ...f, url: url ?? f.url })); setOpen(true); }}><Play className="h-3.5 w-3.5" /> {label}</Button>
      <Modal open={open} onClose={() => setOpen(false)} title="Start a research crawl" footer={<><Button onClick={() => setOpen(false)}>Cancel</Button><Button variant="primary" busy={busy} disabled={form.url.trim().length < 8} onClick={start}>Start research crawl</Button></>}>
        <div className="space-y-4">
          <Field label="Starting URL" hint="An onion address or a web address. Everything is fetched through Tor, as text only, without logging in.">
            <input className="field font-mono" value={form.url} spellCheck={false} placeholder="http://…onion/" onChange={(e) => setForm({ ...form, url: e.target.value })} />
          </Field>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Depth" hint="How many links deep to follow from the starting page, staying on the same site.">
              <select className="field" value={form.depth} onChange={(e) => setForm({ ...form, depth: Number(e.target.value) })}>
                <option value={0}>0 · this page only</option>
                {Array.from({ length: maxDepth }, (_, i) => i + 1).map((d) => <option key={d} value={d}>{d} · {d === 1 ? "pages it links to" : `${d} links deep`}</option>)}
              </select>
            </Field>
            <Field label="Page limit" hint={`Stops after this many pages. Up to ${maxPages}.`}>
              <input className="field" type="number" min={1} max={maxPages} value={form.max_pages} onChange={(e) => setForm({ ...form, max_pages: Math.max(1, Math.min(maxPages, Number(e.target.value) || 1)) })} />
            </Field>
          </div>
          <label className="flex items-start gap-2 text-sm text-ink-2"><input type="checkbox" className="mt-0.5 accent-[var(--accent)]" checked={form.monitor} onChange={(e) => setForm({ ...form, monitor: e.target.checked })} /><span>Keep monitoring this site afterwards. <span className="text-muted">It is then re-crawled on a schedule and changes are recorded as new versions.</span></span></label>
          <p className="text-xs text-muted">Other sites the crawl finds are recorded as discovered sources, not followed. Pages behind a login or CAPTCHA are reported and skipped. Sites on the abuse blocklist are refused.</p>
        </div>
      </Modal>
    </>
  );
}

export function FindingRow({ f, extra }: { f: FindingSummary; extra?: React.ReactNode }) {
  return (
    <div className="flex items-start gap-3 border-b border-line px-4 py-3 last:border-b-0">
      <div className="min-w-0 flex-1">
        <Link href={`/findings/${f.id}`} className="line-clamp-1 text-sm font-medium text-ink hover:text-accent-ink hover:underline">{f.title}</Link>
        <div className="mt-1 flex flex-wrap items-center gap-x-2.5 gap-y-1 text-xs text-muted">
          <SeverityBadge severity={f.severity} />
          <span>{f.threat_label}</span>
          <span>{f.source_name}</span>
          <Countries codes={f.countries} />
          <span title={stamp(f.first_seen)}>{ago(f.first_seen)}</span>
          {f.has_credentials && <CredentialBadge />}
        </div>
        {extra}
      </div>
      <RiskMeter score={f.risk_score} />
    </div>
  );
}

export function Notes({ objectType, objectId }: { objectType: string; objectId: string }) {
  const { me, canWrite } = useSession();
  const { data, mutate, isLoading } = useApi<{ id: number; body: string; user_id: number; user_name: string; created_at: string }[]>(`/notes?object_type=${objectType}&object_id=${objectId}`);
  const [body, setBody] = useState("");
  const { busy, run } = useAction();
  const add = async () => {
    if (await run(() => api("/notes", { method: "POST", body: { object_type: objectType, object_id: objectId, body } }))) { setBody(""); mutate(); }
  };
  return (
    <div>
      {canWrite && (
        <div className="mb-3">
          <textarea value={body} onChange={(e) => setBody(e.target.value)} rows={3} placeholder="Add an analyst note…" className="field h-auto py-2" />
          <div className="mt-2 flex justify-end"><Button variant="primary" size="sm" busy={busy} disabled={!body.trim()} onClick={add}>Add note</Button></div>
        </div>
      )}
      {isLoading ? <Spinner /> : !data?.length ? <p className="py-3 text-sm text-muted">No notes yet.</p> : (
        <ul className="space-y-2">
          {data.map((n) => (
            <li key={n.id} className="rounded-md border border-line bg-raised px-3 py-2">
              <div className="mb-1 flex items-center justify-between text-xs text-muted">
                <span><span className="font-medium text-ink-2">{n.user_name}</span> · {stamp(n.created_at)}</span>
                {(n.user_id === me.id || me.role === "admin") && canWrite && (
                  <button aria-label="Delete note" className="rounded p-1 hover:bg-sunken hover:text-critical" onClick={() => run(() => api(`/notes/${n.id}`, { method: "DELETE" })).then(() => mutate())}><Trash2 className="h-3 w-3" /></button>
                )}
              </div>
              <p className="whitespace-pre-wrap text-sm">{n.body}</p>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export function AddToCase({ objectType, objectId, size = "md", note = "", label = "Add to case" }: { objectType: "finding" | "ioc" | "entity" | "query" | "graph"; objectId: string; size?: "sm" | "md"; note?: string; label?: string }) {
  const { canWrite } = useSession();
  const [open, setOpen] = useState(false);
  const [title, setTitle] = useState("");
  const { data, mutate } = useApi<{ id: number; title: string; status: string; item_count: number }[]>(open ? "/cases" : null);
  const { busy, run } = useAction();
  if (!canWrite) return null;
  const add = async (caseId: number) => {
    if (await run(() => api(`/cases/${caseId}/items`, { method: "POST", body: { object_type: objectType, object_id: objectId, note } }), "Added to case")) setOpen(false);
  };
  const create = async () => {
    await run(async () => {
      const created = await api<{ id: number }>("/cases", { method: "POST", body: { title } });
      await api(`/cases/${created.id}/items`, { method: "POST", body: { object_type: objectType, object_id: objectId, note } });
      setTitle("");
      setOpen(false);
      mutate();
    }, "Case created");
  };
  const openCases = data?.filter((c) => c.status !== "closed") ?? [];
  return (
    <>
      <Button size={size} onClick={() => setOpen(true)}><FolderPlus className="h-3.5 w-3.5" /> {label}</Button>
      <Modal open={open} onClose={() => setOpen(false)} title={label}>
        {!data ? <Spinner /> : openCases.length === 0 ? <Empty title="No open cases" hint="Create one below to start an investigation." /> : (
          <ul className="mb-4 max-h-64 divide-y divide-line overflow-y-auto rounded-md border border-line">
            {openCases.map((c) => (
              <li key={c.id}>
                <button disabled={busy} onClick={() => add(c.id)} className="flex w-full items-center justify-between gap-3 px-3 py-2 text-left text-sm hover:bg-sunken">
                  <span className="truncate">{c.title}</span><span className="shrink-0 text-xs text-muted">{c.item_count} items</span>
                </button>
              </li>
            ))}
          </ul>
        )}
        <Field label="Or start a new case">
          <div className="flex gap-2">
            <input className="field" value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Case title" />
            <Button variant="primary" busy={busy} disabled={title.trim().length < 3} onClick={create}>Create</Button>
          </div>
        </Field>
      </Modal>
    </>
  );
}

export const PRIORITY_TONE: Record<string, "critical" | "serious" | "warning" | "neutral"> = { critical: "critical", high: "serious", medium: "warning", low: "neutral" };

export function TlpBadge({ tlp }: { tlp: string }) {
  const tone = tlp === "red" ? "critical" : tlp === "amber" ? "warning" : tlp === "green" ? "good" : "neutral";
  return <Badge tone={tone} title="Traffic Light Protocol sharing level">TLP:{tlp.toUpperCase()}</Badge>;
}

const VERIFICATION = {
  confirmed: { tone: "good", icon: BadgeCheck, hint: "An analyst confirmed this finding." },
  corroborated: { tone: "good", icon: Users, hint: "Independent sources report the same thing." },
  reported: { tone: "neutral", icon: CircleDot, hint: "Reported by a single source the platform considers reliable." },
  unverified: { tone: "warning", icon: CircleDashed, hint: "A single, low-reliability source. Treat as a claim." },
} as const;

/** How far a finding has been checked, with the Admiralty grade (source reliability + information credibility) when known. */
export function VerificationBadge({ state, admiralty, corroboration }: { state?: string; admiralty?: string; corroboration?: number }) {
  const { meta } = useSession();
  if (!state) return null;
  const v = VERIFICATION[state as keyof typeof VERIFICATION] ?? VERIFICATION.unverified;
  const grade = admiralty && admiralty.length === 2 ? ` Admiralty ${admiralty}: source ${meta.reliability?.[admiralty[0]]?.toLowerCase() ?? admiralty[0]}, information ${meta.credibility?.[admiralty[1]]?.toLowerCase() ?? admiralty[1]}.` : "";
  return (
    <Badge tone={v.tone} title={`${v.hint}${corroboration ? ` Corroborated by ${corroboration} other source${corroboration === 1 ? "" : "s"}.` : ""}${grade}`}>
      <v.icon className="h-3 w-3" />{titleCase(state)}{admiralty ? <span className="font-mono font-normal opacity-80">{admiralty}</span> : null}
    </Badge>
  );
}

/** A score is never shown without the reasons behind it. */
export function FactorList({ factors, total, totalLabel = "Score" }: { factors: Factor[]; total?: number; totalLabel?: string }) {
  if (!factors?.length) return <p className="px-4 py-3 text-sm text-muted">No contributing factors recorded.</p>;
  return (
    <ul className="px-4 py-2 text-sm">
      {factors.map((r, i) => (
        <li key={i} className="flex items-baseline justify-between gap-3 py-1">
          <span className="text-ink-2">{r.factor}</span>
          <span className={cn("shrink-0 tabular-nums", r.points < 0 ? "text-good" : "text-ink")}>{r.points > 0 ? "+" : ""}{r.points}</span>
        </li>
      ))}
      {total !== undefined && <li className="mt-1 flex justify-between border-t border-line pt-2 font-semibold"><span>{totalLabel}</span><span className="tabular-nums">{total} / 100</span></li>}
    </ul>
  );
}

export interface AiSource { label: string; id: string; title: string; source_name?: string; date?: string }
export interface AiJob {
  status: "idle" | "queued" | "translating" | "retrieving" | "answering" | "done" | "error" | "disabled";
  error?: string; message?: string; query?: string; explanation?: string; answer?: string; text?: string; summary?: string; key_points?: string[];
  recommended_actions?: string[]; citations?: string[]; confidence?: string; gaps?: string; sources?: AiSource[]; interpretation?: { kind: string; label: string; detail: string }[];
}
const AI_STEPS: Record<string, string> = { queued: "Queued", translating: "Working out what to search for", retrieving: "Retrieving matching findings", answering: "Reading the findings" };

/** Start an AI job and poll it. The model runs in the isolated enricher, so results arrive asynchronously. */
export function useAiJob() {
  const [job, setJob] = useState<AiJob>({ status: "idle" });
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const stop = useCallback(() => { if (timer.current) clearTimeout(timer.current); timer.current = null; }, []);
  useEffect(() => stop, [stop]);
  const start = useCallback(async (path: string, body: unknown) => {
    stop();
    setJob({ status: "queued" });
    try {
      const first = await api<AiJob & { job_id?: string }>(path, { method: "POST", body });
      if (!first.job_id) return setJob(first);
      const started = Date.now();
      const poll = async () => {
        try {
          const next = await api<AiJob>(`/ai/jobs/${first.job_id}`);
          setJob(next);
          if (next.status === "done" || next.status === "error") return;
          if (Date.now() - started > 300000) return setJob({ status: "error", error: "The request took too long. Try again." });
          timer.current = setTimeout(poll, 1500);
        } catch (err) { setJob({ status: "error", error: err instanceof Error ? err.message : "The request failed" }); }
      };
      timer.current = setTimeout(poll, 1200);
    } catch (err) { setJob({ status: "error", error: err instanceof Error ? err.message : "The request failed" }); }
  }, [stop]);
  const reset = useCallback(() => { stop(); setJob({ status: "idle" }); }, [stop]);
  return { job, start, reset, busy: job.status in AI_STEPS, step: AI_STEPS[job.status] ?? "" };
}

/** Model output is plain text. Citation markers such as [S2] become links to the finding they refer to; nothing else is interpreted. */
export function CitedText({ text, sources }: { text: string; sources?: AiSource[] }) {
  const byLabel = new Map((sources ?? []).map((s) => [s.label, s]));
  return (
    <p className="whitespace-pre-wrap text-sm leading-relaxed text-ink">
      {text.split(/(\[S\d+\])/g).map((part, i) => {
        const source = /^\[S\d+\]$/.test(part) ? byLabel.get(part.slice(1, -1)) : undefined;
        return source ? <Link key={i} href={`/findings/${source.id}`} title={source.title} className="mx-0.5 rounded bg-accent-soft px-1 font-mono text-2xs font-semibold text-accent-ink hover:underline">{source.label}</Link> : <span key={i}>{part}</span>;
      })}
    </p>
  );
}

export function AiSources({ sources, cited }: { sources?: AiSource[]; cited?: string[] }) {
  const shown = (sources ?? []).filter((s) => !cited?.length || cited.includes(s.label));
  if (!shown.length) return null;
  return (
    <ol className="mt-3 space-y-1 border-t border-line pt-3 text-xs">
      {shown.map((s) => (
        <li key={s.label} className="flex items-baseline gap-2">
          <span className="shrink-0 rounded bg-accent-soft px-1 font-mono text-2xs font-semibold text-accent-ink">{s.label}</span>
          <Link href={`/findings/${s.id}`} className="min-w-0 truncate text-ink-2 hover:underline">{s.title}</Link>
          {s.source_name && <span className="shrink-0 text-muted">{s.source_name}</span>}
        </li>
      ))}
    </ol>
  );
}

export function AiLabel({ children }: { children?: React.ReactNode }) {
  return <span className="inline-flex items-center gap-1 text-xs font-medium text-accent-ink"><Sparkles className="h-3.5 w-3.5" />{children ?? "AI-drafted from collected findings. Check it against the cited sources."}</span>;
}

/** Pin the current capture of a page into an investigation, so it stays there whatever happens to the site. */
export function PreserveEvidence({ findingId }: { findingId: string }) {
  const { canWrite } = useSession();
  const [open, setOpen] = useState(false);
  const [note, setNote] = useState("");
  const { data: cases } = useApi<{ id: number; title: string; status: string }[]>(open ? "/cases" : null);
  const { busy, run } = useAction();
  if (!canWrite) return null;
  const openCases = cases?.filter((c) => c.status !== "closed") ?? [];
  const preserve = async (caseId: number) => {
    if (await run(() => api(`/findings/${findingId}/preserve`, { method: "POST", body: { case_id: caseId, note } }), "Evidence preserved in the investigation")) { setOpen(false); setNote(""); }
  };
  return (
    <>
      <Button onClick={() => setOpen(true)} title="Keep this exact capture, with its hashes, in an investigation"><BadgeCheck className="h-3.5 w-3.5" /> Preserve evidence</Button>
      <Modal open={open} onClose={() => setOpen(false)} title="Preserve evidence">
        <p className="mb-3 text-sm text-ink-2">Records the capture as it is now: its address, when it was collected, its text, the hash of the original and of the stored text, your name and the investigation. It stays available if the source changes or disappears.</p>
        <Field label="Why it matters (optional)"><textarea className="field h-20 py-2" value={note} onChange={(e) => setNote(e.target.value)} placeholder="What this shows" /></Field>
        <div className="label mb-1 mt-4">Preserve in</div>
        {!cases ? <Spinner /> : openCases.length === 0 ? <Empty title="No open investigations" hint="Create one first, from Investigations or with “Add to investigation”." /> : (
          <ul className="max-h-60 divide-y divide-line overflow-y-auto rounded-md border border-line">
            {openCases.map((c) => <li key={c.id}><button disabled={busy} onClick={() => preserve(c.id)} className="w-full px-3 py-2 text-left text-sm hover:bg-sunken">{c.title}</button></li>)}
          </ul>
        )}
      </Modal>
    </>
  );
}

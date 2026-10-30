"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { PageHeader } from "@/components/shell";
import { Badge, Button, Card, CardHeader, Empty, ErrorNote, Spinner } from "@/components/ui";
import { useApi } from "@/lib/api";
import { day, defang, num } from "@/lib/format";

interface Event {
  id: string; date: string; title: string; type: string; type_label: string; severity: string; risk: number;
  actor: string | null; actor_id: number | null; lane: number | "other" | null; victims: string[];
  countries: { code: string; name: string }[]; sectors: string[]; source: string; network: string;
}
interface LinkRow { a: string; b: string; kind: "victim" | "relisted" | "vulnerability" | "indicator"; label: string }
interface Timeline {
  days: number; events: Event[]; lanes: { id: number; name: string; count: number }[]; links: LinkRow[];
  truncated: boolean; types: { value: string; label: string; count: number }[]; unattributed: number;
  possible_aliases?: { a: { id: number; name: string }; b: { id: number; name: string }; shared_victims: number }[];
}

// Fixed colour per type, whatever the filter: colour follows the type, not its rank.
const TYPE_COLOR: Record<string, string> = {
  ransomware: "var(--series-1)", vulnerability: "var(--series-2)", data_breach: "var(--series-3)", malware: "var(--series-4)",
  phishing: "var(--series-5)", credential_leak: "var(--series-6)", access_sale: "var(--series-7)",
};
const colorOf = (type: string) => TYPE_COLOR[type] ?? "var(--muted)";
const LINK_DASH: Record<string, string | undefined> = { victim: undefined, relisted: "8 4", vulnerability: "4 3", indicator: "1.5 3" };
const LINK_LABEL: Record<string, string> = { victim: "Same victim, different actors", relisted: "Reported again", vulnerability: "Same CVE", indicator: "Shared indicator" };

const LABEL_W = 132;
const ROW_H = 30;
const PAD_T = 26;
const PLOT_MIN = 640;

/** Width of an element that may mount later (after data loads): a callback ref, so it is measured whenever it appears. */
function useWidth() {
  const ref = useRef<HTMLDivElement | null>(null);
  const [node, setNode] = useState<HTMLDivElement | null>(null);
  const [width, setWidth] = useState(0);
  const attach = useCallback((el: HTMLDivElement | null) => { ref.current = el; setNode(el); }, []);
  useEffect(() => {
    if (!node) return;
    const obs = new ResizeObserver(([e]) => setWidth(Math.floor(e.contentRect.width)));
    obs.observe(node);
    return () => obs.disconnect();
  }, [node]);
  return [ref, attach, width] as const;
}

function TimelineView() {
  const params = useSearchParams();
  const router = useRouter();
  const days = Number(params.get("days") ?? 30);
  const type = params.get("type") ?? "";
  const actor = params.get("actor") ?? "";
  const qs = new URLSearchParams({ days: String(days), ...(type ? { type } : {}), ...(actor ? { actor } : {}) }).toString();
  const { data, error } = useApi<Timeline>(`/timeline?${qs}`);
  const [box, attachBox, width] = useWidth();
  const [hover, setHover] = useState<{ e: Event; x: number; y: number } | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const set = (next: Record<string, string>) => {
    const p = new URLSearchParams({ days: String(days), ...(type ? { type } : {}), ...(actor ? { actor } : {}), ...next });
    for (const [k, v] of [...p.entries()]) if (!v) p.delete(k);
    setSelected(null);
    router.replace(`/timeline?${p.toString()}`);
  };

  const layout = useMemo(() => {
    if (!data) return null;
    const rows: { key: string; label: string; actorId?: number; count: number }[] = data.lanes.map((l) => ({ key: String(l.id), label: l.name, actorId: l.id, count: l.count }));
    const other = data.events.filter((e) => e.lane === "other").length;
    if (other) rows.push({ key: "other", label: "Other actors", count: other });
    if (data.unattributed) rows.push({ key: "none", label: "No named actor", count: data.unattributed });
    const rowOf = (e: Event) => rows.findIndex((r) => r.key === (e.lane === null ? "none" : String(e.lane)));
    const plotW = Math.max(PLOT_MIN, width - LABEL_W - 12);
    const end = Date.now();
    const start = end - data.days * 86400000;
    const x = (iso: string) => LABEL_W + Math.max(0, Math.min(1, (new Date(iso).getTime() - start) / (end - start))) * plotW;
    // Spread events that share a day and a row vertically, so none hides another.
    const slot = new Map<string, number>();
    const pos = new Map<string, { x: number; y: number }>();
    for (const e of [...data.events].sort((a, b) => a.date.localeCompare(b.date))) {
      const r = rowOf(e);
      const k = `${r}:${e.date.slice(0, 10)}`;
      const n = slot.get(k) ?? 0;
      slot.set(k, n + 1);
      const offset = ((n % 5) - 2) * 4.5;
      pos.set(e.id, { x: x(e.date), y: PAD_T + r * ROW_H + ROW_H / 2 + offset });
    }
    const stepDays = data.days <= 7 ? 1 : data.days <= 31 ? 7 : data.days <= 92 ? 14 : 30;
    const ticks: { x: number; label: string }[] = [];
    for (let t = start; t <= end; t += stepDays * 86400000) ticks.push({ x: x(new Date(t).toISOString()), label: day(new Date(t).toISOString()) });
    return { rows, pos, plotW, ticks, height: PAD_T + rows.length * ROW_H + 8, svgW: LABEL_W + plotW + 8 };
  }, [data, width]);

  const byId = useMemo(() => new Map((data?.events ?? []).map((e) => [e.id, e])), [data]);
  const active = hover?.e.id ?? selected;
  const activeLinks = useMemo(() => new Set((data?.links ?? []).filter((l) => l.a === active || l.b === active).flatMap((l) => [l.a, l.b])), [data, active]);
  const sel = selected ? byId.get(selected) : undefined;
  const selLinks = (data?.links ?? []).filter((l) => sel && (l.a === sel.id || l.b === sel.id));

  return (
    <>
      <PageHeader title="Event timeline" subtitle="Incidents over time, one row per threat actor. Lines join events that hit the same victim, exploit the same CVE, or share an indicator across sources." />
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <div className="inline-flex rounded-md border border-line p-0.5">
          {[7, 30, 90].map((d) => <button key={d} onClick={() => set({ days: String(d) })} className={`rounded px-2.5 py-1 text-xs ${d === days ? "bg-accent-soft text-accent-ink" : "text-ink-2 hover:text-ink"}`}>{d} days</button>)}
        </div>
        <select className="field h-8 w-auto px-2 text-xs" value={type} onChange={(e) => set({ type: e.target.value })} aria-label="Event type">
          <option value="">All event types</option>
          {(data?.types ?? []).map((t) => <option key={t.value} value={t.value}>{t.label} ({t.count})</option>)}
        </select>
        {actor && <Button size="sm" onClick={() => set({ actor: "" })}>Show all actors</Button>}
        {data?.truncated && <span className="text-xs text-muted">Showing the {num(data.events.length)} most recent events; narrow the period or type to see the rest.</span>}
      </div>

      {error && <ErrorNote error={error} />}
      {!data && !error && <Spinner />}
      {data && data.events.length === 0 && <Empty title="No events in this period" hint="Try a longer period, or another event type." />}
      {data && layout && data.events.length > 0 && (
        <Card>
          <div ref={attachBox} className="relative">
            <div className="scroll-thin overflow-x-auto" onPointerLeave={() => setHover(null)}>
              <svg width={layout.svgW} height={layout.height} role="img" aria-label={`Timeline of ${data.events.length} events over ${data.days} days`} className="block">
                {layout.ticks.map((t) => (
                  <g key={t.x}>
                    <line x1={t.x} x2={t.x} y1={PAD_T - 6} y2={layout.height - 8} stroke="var(--line)" />
                    <text x={t.x} y={14} textAnchor="middle" className="fill-[var(--muted)] text-[10px]">{t.label}</text>
                  </g>
                ))}
                {layout.rows.map((r, i) => (
                  <g key={r.key}>
                    {i % 2 === 1 && <rect x={0} y={PAD_T + i * ROW_H} width={layout.svgW} height={ROW_H} fill="var(--sunken)" opacity={0.45} />}
                    <text x={8} y={PAD_T + i * ROW_H + ROW_H / 2 + 4} className={`text-[11px] ${r.actorId ? "cursor-pointer fill-[var(--ink)] hover:underline" : "fill-[var(--muted)]"}`}
                          onClick={r.actorId ? () => set({ actor: String(r.actorId) }) : undefined}>
                      {r.label.length > 17 ? `${r.label.slice(0, 16)}…` : r.label} <tspan className="fill-[var(--muted)]">{r.count}</tspan>
                      <title>{r.actorId ? `${r.label}: ${r.count} events. Click to show only this actor.` : `${r.label}: ${r.count} events`}</title>
                    </text>
                  </g>
                ))}
                {data.links.map((l, i) => {
                  const a = layout.pos.get(l.a), b = layout.pos.get(l.b);
                  if (!a || !b) return null;
                  const lit = active && (l.a === active || l.b === active);
                  const faint = l.kind === "relisted" && !lit; // a repeat of the same claim recedes behind real connections
                  const mid = (a.x + b.x) / 2, lift = Math.min(40, Math.abs(b.x - a.x) / 3 + 8);
                  return <path key={i} d={`M${a.x},${a.y} Q${mid},${Math.min(a.y, b.y) - lift} ${b.x},${b.y}`} fill="none" stroke={lit ? "var(--ink)" : "var(--ink-2)"}
                               strokeWidth={lit ? 1.6 : 1} strokeDasharray={LINK_DASH[l.kind]} opacity={active ? (lit ? 0.95 : 0.08) : faint ? 0.18 : 0.4} />;
                })}
                {data.events.map((e) => {
                  const p = layout.pos.get(e.id);
                  if (!p) return null;
                  const dim = active && e.id !== active && !activeLinks.has(e.id);
                  return (
                    <g key={e.id} className="cursor-pointer" opacity={dim ? 0.25 : 1}
                       onPointerMove={(ev) => { const r = box.current?.getBoundingClientRect(); if (r) setHover({ e, x: ev.clientX - r.left, y: ev.clientY - r.top }); }}
                       onClick={() => setSelected(e.id === selected ? null : e.id)}>
                      <circle cx={p.x} cy={p.y} r={10} fill="transparent" />
                      <circle cx={p.x} cy={p.y} r={e.id === selected ? 6 : e.severity === "critical" || e.severity === "high" ? 4.5 : 3.5}
                              fill={colorOf(e.type)} stroke="var(--surface)" strokeWidth={1.5} />
                    </g>
                  );
                })}
              </svg>
            </div>
            {hover && (
              <div className="pointer-events-none absolute z-10 w-64 rounded-md border border-line bg-raised px-3 py-2 text-xs shadow-md"
                   style={{ left: Math.max(4, Math.min(hover.x + 14, (box.current?.clientWidth ?? 300) - 270)), top: hover.y + 14 }}>
                <div className="text-muted">{day(hover.e.date)} · {hover.e.type_label}</div>
                <div className="mt-0.5 line-clamp-3 font-medium text-ink">{hover.e.title}</div>
                <div className="mt-1 text-ink-2">{hover.e.actor ?? "No named actor"}{hover.e.victims.length ? ` → ${hover.e.victims.join(", ")}` : ""}</div>
                <div className="mt-0.5 text-muted">{hover.e.source}{hover.e.countries.length ? ` · ${hover.e.countries.map((c) => c.name).join(", ")}` : ""}</div>
              </div>
            )}
          </div>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-line px-4 py-2 text-2xs text-muted">
            {data.types.filter((t) => TYPE_COLOR[t.value]).map((t) => <span key={t.value} className="flex items-center gap-1"><span className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: colorOf(t.value) }} />{t.label}</span>)}
            {data.types.some((t) => !TYPE_COLOR[t.value]) && <span className="flex items-center gap-1"><span className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: "var(--muted)" }} />Other types</span>}
            <span className="mx-1 h-3 w-px bg-line" />
            {(["victim", "relisted", "vulnerability", "indicator"] as const).map((k) => (
              <span key={k} className="flex items-center gap-1"><svg width="22" height="6"><line x1="1" x2="21" y1="3" y2="3" stroke="var(--ink-2)" strokeWidth="1.4" strokeDasharray={LINK_DASH[k]} /></svg>{LINK_LABEL[k]} ({data.links.filter((l) => l.kind === k).length})</span>
            ))}
            <span>Larger dots are high or critical severity.</span>
          </div>
        </Card>
      )}

      {data && (data.possible_aliases ?? []).length > 0 && (
        <Card className="mt-4">
          <CardHeader title="Possibly the same actor" hint="Names that keep claiming the same victims. Trackers often spell one group differently; check the profiles and merge if they match." />
          <ul className="divide-y divide-line">
            {(data.possible_aliases ?? []).map((p) => (
              <li key={`${p.a.id}-${p.b.id}`} className="flex flex-wrap items-center gap-2 px-4 py-2 text-sm">
                <Link className="text-accent-ink hover:underline" href={`/entities/${p.a.id}`}>{p.a.name}</Link>
                <span className="text-muted">and</span>
                <Link className="text-accent-ink hover:underline" href={`/entities/${p.b.id}`}>{p.b.name}</Link>
                <span className="ml-auto text-xs tabular-nums text-muted">{p.shared_victims} shared victims</span>
              </li>
            ))}
          </ul>
        </Card>
      )}

      {sel && (
        <Card className="mt-4">
          <CardHeader title={sel.title} hint={`${day(sel.date)} · ${sel.type_label} · ${sel.source}`} action={<Link href={`/findings/${sel.id}`}><Button size="sm">Open finding</Button></Link>} />
          <div className="grid gap-4 px-4 py-3 text-sm md:grid-cols-2">
            <dl className="space-y-2">
              <div><dt className="label">Actor</dt><dd>{sel.actor_id ? <Link className="text-accent-ink hover:underline" href={`/entities/${sel.actor_id}`}>{sel.actor}</Link> : "No named actor"}</dd></div>
              <div><dt className="label">Victims</dt><dd>{sel.victims.join(", ") || "—"}</dd></div>
              <div><dt className="label">Countries</dt><dd>{sel.countries.map((c) => c.name).join(", ") || "—"}</dd></div>
              <div><dt className="label">Sectors</dt><dd>{sel.sectors.join(", ") || "—"}</dd></div>
            </dl>
            <div>
              <div className="label mb-1">Connected events ({selLinks.length})</div>
              {selLinks.length === 0 ? <p className="text-muted">None in this period.</p> : (
                <ul className="divide-y divide-line">
                  {selLinks.map((l, i) => {
                    const other = byId.get(l.a === sel.id ? l.b : l.a);
                    return other ? (
                      <li key={i} className="py-1.5">
                        <button className="text-left hover:underline" onClick={() => setSelected(other.id)}>{other.title.slice(0, 90)}</button>
                        <div className="text-xs text-muted"><Badge>{LINK_LABEL[l.kind]}</Badge> <span className="font-mono">{(l.kind === "indicator" ? defang(l.label) : l.label).slice(0, 60)}</span> · {day(other.date)} · {other.actor ?? "no named actor"}</div>
                      </li>
                    ) : null;
                  })}
                </ul>
              )}
            </div>
          </div>
        </Card>
      )}
    </>
  );
}

export default function Page() {
  return <Suspense fallback={<Spinner />}><TimelineView /></Suspense>;
}

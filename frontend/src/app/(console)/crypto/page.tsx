"use client";

import { forceCollide, forceLink, forceManyBody, forceSimulation, forceX, forceY, type SimulationLinkDatum, type SimulationNodeDatum } from "d3-force";
import { ArrowRight, Coins, Copy, Maximize2, Minus, Plus, Search } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useCallback, useEffect, useMemo, useRef, useState, type FormEvent, type PointerEvent as ReactPointerEvent } from "react";
import { AddToCase, FindingRow } from "@/components/bits";
import { PageHeader } from "@/components/shell";
import { useSession } from "@/components/session";
import { Badge, Button, Card, CardHeader, CopyButton, Empty, ErrorNote, Spinner, useAction, useToast } from "@/components/ui";
import { api, useApi, type ChainEdge, type ChainGraph, type ChainNode } from "@/lib/api";
import { ago, cn, day, num } from "@/lib/format";

// Category -> colour and whether it is noteworthy. Risk categories stand out, like severity does for findings.
const CATEGORY: Record<string, { tone: string; dot: string }> = {
  sanctioned: { tone: "critical", dot: "var(--critical)" },
  mixer: { tone: "critical", dot: "var(--critical)" },
  service: { tone: "serious", dot: "var(--series-2)" },
  exchange: { tone: "accent", dot: "var(--series-1)" },
  distributor: { tone: "warning", dot: "var(--warning)" },
  collector: { tone: "warning", dot: "var(--series-4)" },
  intel: { tone: "critical", dot: "var(--series-5)" },
  "wallet-cluster": { tone: "neutral", dot: "var(--series-7)" },
  personal: { tone: "neutral", dot: "var(--series-3)" },
  unknown: { tone: "neutral", dot: "var(--muted)" },
};
const amount = (v: number | null | undefined, token: string) => (v === null || v === undefined ? "—" : `${v >= 1000 ? num(Math.round(v)) : v >= 1 ? v.toFixed(2) : v.toPrecision(3)} ${token.split(" ")[0]}`);

interface GNode extends SimulationNodeDatum, ChainNode { root?: boolean }
interface GEdge extends SimulationLinkDatum<GNode>, ChainEdge { source: string | GNode; target: string | GNode }

function layout(graph: ChainGraph) {
  const nodes: GNode[] = graph.nodes.map((n) => ({ ...n, root: n.address === graph.address }));
  const byId = new Map(nodes.map((n) => [n.address, n]));
  const edges: GEdge[] = graph.edges.filter((e) => byId.has(e.src) && byId.has(e.dst)).map((e) => ({ ...e, source: e.src, target: e.dst }));
  const sim = forceSimulation(nodes)
    .force("link", forceLink<GNode, GEdge>(edges).id((d) => d.address).distance(130).strength(0.5))
    .force("charge", forceManyBody().strength(-500))
    .force("collide", forceCollide<GNode>().radius((d) => radius(d) + 28))
    .force("x", forceX(0).strength(0.05))
    .force("y", forceY(0).strength(0.06))
    .stop();
  for (let i = 0; i < 320; i++) sim.tick();
  return { nodes, edges };
}
const radius = (n: GNode) => (n.root ? 17 : n.enriched ? Math.min(15, 7 + Math.log10((n.tx_count ?? 1) + 1) * 3) : 7);

function Graph({ graph, selected, onSelect, onExpand }: { graph: ChainGraph; selected: string; onSelect: (a: string) => void; onExpand: (a: string) => void }) {
  const { nodes, edges } = useMemo(() => layout(graph), [graph]);
  const [view, setView] = useState({ x: 0, y: 0, k: 1 });
  const drag = useRef<{ x: number; y: number; vx: number; vy: number } | null>(null);
  useEffect(() => setView({ x: 0, y: 0, k: 1 }), [graph.address]);
  const bounds = useMemo(() => {
    const xs = nodes.map((n) => n.x ?? 0), ys = nodes.map((n) => n.y ?? 0), pad = 110;
    const minX = Math.min(...xs) - pad, maxX = Math.max(...xs) + pad, minY = Math.min(...ys) - pad, maxY = Math.max(...ys) + pad;
    return { x: minX, y: minY, w: Math.max(maxX - minX, 400), h: Math.max(maxY - minY, 300) };
  }, [nodes]);
  const focus = selected || graph.address;
  const neighbours = useMemo(() => {
    const set = new Set<string>([focus]);
    edges.forEach((e) => { const s = (e.source as GNode).address, t = (e.target as GNode).address; if (s === focus) set.add(t); if (t === focus) set.add(s); });
    return set;
  }, [edges, focus]);
  const onDown = (e: ReactPointerEvent<SVGSVGElement>) => { drag.current = { x: e.clientX, y: e.clientY, vx: view.x, vy: view.y }; };
  const onMove = (e: ReactPointerEvent<SVGSVGElement>) => {
    if (!drag.current) return;
    const scale = bounds.w / e.currentTarget.clientWidth / view.k;
    setView((v) => ({ ...v, x: drag.current!.vx - (e.clientX - drag.current!.x) * scale, y: drag.current!.vy - (e.clientY - drag.current!.y) * scale }));
  };
  const zoom = (f: number) => setView((v) => ({ ...v, k: Math.min(4, Math.max(0.4, v.k * f)) }));
  const w = bounds.w / view.k, h = bounds.h / view.k;
  const viewBox = `${bounds.x + view.x + (bounds.w - w) / 2} ${bounds.y + view.y + (bounds.h - h) / 2} ${w} ${h}`;

  return (
    <Card className="relative overflow-hidden">
      <div className="absolute right-3 top-3 z-10 flex flex-col gap-1">
        <Button size="sm" aria-label="Zoom in" onClick={() => zoom(1.25)}><Plus className="h-3.5 w-3.5" /></Button>
        <Button size="sm" aria-label="Zoom out" onClick={() => zoom(0.8)}><Minus className="h-3.5 w-3.5" /></Button>
        <Button size="sm" aria-label="Reset" onClick={() => setView({ x: 0, y: 0, k: 1 })}><Maximize2 className="h-3.5 w-3.5" /></Button>
      </div>
      <svg viewBox={viewBox} className="h-[600px] w-full cursor-grab touch-none select-none active:cursor-grabbing" role="img" aria-label="Transaction flow graph"
        onPointerDown={onDown} onPointerMove={onMove} onPointerUp={() => (drag.current = null)} onPointerLeave={() => (drag.current = null)} onWheel={(e) => zoom(e.deltaY < 0 ? 1.1 : 0.9)}>
        <defs>
          <marker id="flow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="var(--line-strong)" /></marker>
        </defs>
        {edges.map((e, i) => {
          const s = e.source as GNode, t = e.target as GNode;
          const lit = s.address === focus || t.address === focus;
          return (
            <g key={i} opacity={lit ? 1 : 0.5}>
              <line x1={s.x} y1={s.y} x2={t.x} y2={t.y} stroke={lit ? "var(--accent)" : "var(--line-strong)"} strokeWidth={Math.min(4, 0.8 + Math.log10(e.value + 1) * 1.2)} markerEnd="url(#flow)" />
              {lit && <text x={((s.x ?? 0) + (t.x ?? 0)) / 2} y={((s.y ?? 0) + (t.y ?? 0)) / 2 - 3} textAnchor="middle" fontSize={9} fill="var(--ink-2)" stroke="var(--surface)" strokeWidth={3} paintOrder="stroke" pointerEvents="none">{amount(e.value, graph.root.token || "")}</text>}
            </g>
          );
        })}
        {nodes.map((n) => {
          const st = CATEGORY[n.category] ?? CATEGORY.unknown, r = radius(n), dim = !neighbours.has(n.address);
          return (
            <g key={n.address} transform={`translate(${n.x},${n.y})`} opacity={dim ? 0.3 : 1} className="cursor-pointer"
              onPointerDown={(e) => e.stopPropagation()} onClick={() => onSelect(n.address)} onDoubleClick={() => n.enriched || onExpand(n.address)}>
              <title>{`${n.category_label}${n.label ? `: ${n.label}` : ""} — ${n.defanged}`}</title>
              {n.enriched ? <circle r={r} fill={st.dot} stroke="var(--surface)" strokeWidth={2} /> : <circle r={r} fill="var(--sunken)" stroke={st.dot} strokeWidth={2} strokeDasharray="3 2" />}
              {n.risk && <circle r={r + 3.5} fill="none" stroke="var(--critical)" strokeWidth={1.5} />}
              {(n.root || n.address === selected) && <circle r={r + 6} fill="none" stroke="var(--accent)" strokeWidth={2} />}
              <text y={r + 13} textAnchor="middle" fontSize={10} fontWeight={n.root ? 700 : 500} fill="var(--ink)" stroke="var(--surface)" strokeWidth={3} paintOrder="stroke" className="font-mono">{n.defanged}</text>
            </g>
          );
        })}
      </svg>
      <div className="flex flex-wrap gap-x-4 gap-y-1 border-t border-line px-4 py-2 text-xs text-ink-2">
        {["sanctioned", "exchange", "service", "distributor", "intel", "personal", "unknown"].map((c) => (
          <span key={c} className="inline-flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full" style={{ background: CATEGORY[c].dot }} />{{ sanctioned: "Sanctioned", exchange: "Exchange", service: "Service", distributor: "Distributor", intel: "In intelligence", personal: "Personal", unknown: "Not looked up" }[c]}</span>
        ))}
        <span className="ml-auto text-muted">Arrow = direction of funds · line weight = amount · dashed = not looked up · double-click to expand</span>
      </div>
    </Card>
  );
}

function CryptoPage() {
  const params = useSearchParams();
  const router = useRouter();
  const { canWrite } = useSession();
  const toast = useToast();
  const address = params.get("address") ?? "";
  const [input, setInput] = useState(address);
  const [busy, setBusy] = useState(false);
  const [selected, setSelected] = useState("");
  const { data, error, isLoading, mutate } = useApi<ChainGraph>(address ? `/chain/${encodeURIComponent(address)}` : null);
  const { run } = useAction();
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => () => { if (timer.current) clearTimeout(timer.current); }, []);
  useEffect(() => { setInput(address); setSelected(""); }, [address]);

  const go = (addr: string) => router.push(`/crypto?address=${encodeURIComponent(addr.trim())}`);
  const poll = useCallback((jobId: string, after: () => void) => {
    const started = Date.now();
    const tick = async () => {
      try {
        const job = await api<{ status: string; error?: string }>(`/chain/jobs/${jobId}`);
        if (job.status === "done" || job.status === "error") { setBusy(false); if (job.error) toast(job.error, "critical"); return after(); }
      } catch { /* keep polling */ }
      if (Date.now() - started > 120000) { setBusy(false); return toast("The lookup took too long.", "critical"); }
      timer.current = setTimeout(tick, 1500);
    };
    timer.current = setTimeout(tick, 1200);
  }, [toast]);

  const lookup = async (e?: FormEvent) => {
    e?.preventDefault();
    const addr = input.trim();
    if (addr.length < 10) return;
    setBusy(true);
    try {
      const out = await api<{ address: string; chain: string; supported: boolean; job_id: string | null }>("/chain/lookup", { method: "POST", body: { address: addr } });
      if (addr.toLowerCase() !== out.address.toLowerCase()) return go(out.address);
      if (!out.supported || !out.job_id) { setBusy(false); return mutate(); }
      poll(out.job_id, () => mutate());
    } catch (err) { setBusy(false); toast(err instanceof Error ? err.message : "Lookup failed", "critical"); }
  };
  const expand = (addr: string) => {
    setBusy(true);
    run(async () => {
      const out = await api<{ queued: number; job_ids: string[] }>(`/chain/${encodeURIComponent(addr)}/expand`, { method: "POST" });
      if (out.queued === 0) { setBusy(false); return toast("Every counterparty has already been looked up."); }
      let left = out.job_ids.length;
      out.job_ids.forEach((j) => poll(j, () => { if (--left <= 0) { setBusy(false); mutate(); } }));
    });
  };

  const node = data?.nodes.find((n) => n.address === (selected || data.address)) ?? data?.root;

  return (
    <>
      <PageHeader title="Crypto tracer" subtitle="Trace a Bitcoin, Ethereum or TRON (USDT) wallet: balance, flow of funds, and where it appears in collected dark-web intelligence. Expand a counterparty to follow the money. Read-only public blockchain data." />
      <form onSubmit={lookup} className="relative mb-4 max-w-2xl" role="search">
        <Coins className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
        <input value={input} onChange={(e) => setInput(e.target.value)} autoFocus spellCheck={false} aria-label="Wallet address"
          placeholder="Paste a wallet address: bc1…, 1…, 3…, 0x…, or T…" className="h-11 w-full rounded-lg border border-line-strong bg-raised pl-10 pr-28 font-mono text-sm placeholder:font-sans placeholder:text-muted" />
        <Button variant="primary" type="submit" busy={busy} className="absolute right-1 top-1/2 -translate-y-1/2">Trace</Button>
      </form>

      <ErrorNote error={error} />
      {!address ? <Card><Empty title="Trace a wallet" hint="Paste any Bitcoin, Ethereum or TRON address above. You can also reach this from the Trace button on any crypto indicator." /></Card>
        : isLoading && !data ? <Spinner label="Loading" />
        : data && (
          <>
            {data.note && <p className="mb-3 rounded-md border border-line bg-warning-soft px-3 py-2 text-sm">{data.note}</p>}
            {!data.enriched && data.can_look_up && (
              <div className="mb-3 flex flex-wrap items-center gap-3 rounded-md border border-line bg-accent-soft px-3 py-2 text-sm">
                <span>This address has not been looked up yet.</span>{canWrite && <Button size="sm" busy={busy} onClick={() => lookup()}>Look it up</Button>}
              </div>
            )}
            <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_22rem]">
              <div className="min-w-0 space-y-4">
                {data.nodes.length > 1 ? <Graph graph={data} selected={selected} onSelect={setSelected} onExpand={expand} />
                  : <Card><Empty title={data.enriched ? "No flows found" : "Look it up to draw the graph"} hint={data.enriched ? "No counterparties were found in the transactions examined." : undefined} /></Card>}
                {data.findings.length > 0 && (
                  <Card>
                    <CardHeader title={`Seen in collected intelligence (${data.findings.length})`} hint="Findings where this wallet appears" />
                    {data.findings.map((f) => <FindingRow key={f.id} f={f} />)}
                  </Card>
                )}
              </div>
              <aside className="min-w-0 space-y-4">
                {node && (
                  <Card>
                    <CardHeader title={<span className="inline-flex items-center gap-1.5">{node.category_label}{node.risk && <Badge tone="critical">Noteworthy</Badge>}</span>} hint={node.label || undefined} />
                    <div className="space-y-2 px-4 py-3 text-sm">
                      <div className="flex items-center gap-1"><code className="min-w-0 flex-1 break-all font-mono text-xs">{node.address}</code><CopyButton value={node.address} /></div>
                      <dl className="grid grid-cols-2 gap-2">
                        <div><dt className="label">Chain</dt><dd>{data.chain_label}</dd></div>
                        <div><dt className="label">Balance</dt><dd className="tabular-nums">{amount(node.balance, node.token || data.root.token)}</dd></div>
                        <div><dt className="label">Received</dt><dd className="tabular-nums">{amount(node.total_in, node.token || data.root.token)}</dd></div>
                        <div><dt className="label">Sent</dt><dd className="tabular-nums">{amount(node.total_out, node.token || data.root.token)}</dd></div>
                        <div><dt className="label">Transactions</dt><dd className="tabular-nums">{node.tx_count === null ? "—" : num(node.tx_count)}{node.truncated ? "+" : ""}</dd></div>
                        <div><dt className="label">Counterparties</dt><dd className="tabular-nums">{node.counterparty_count ?? "—"}</dd></div>
                        {node.first_tx && <div><dt className="label">First activity</dt><dd>{day(node.first_tx)}</dd></div>}
                        {node.last_tx && <div><dt className="label">Last activity</dt><dd>{ago(node.last_tx)}</dd></div>}
                      </dl>
                      {node.in_intel && <Badge tone="critical">Appears in collected intelligence</Badge>}
                      {(node.co_spent?.length ?? 0) > 0 && <p className="text-xs text-muted">Likely same wallet as {node.co_spent!.length} co-spent address{node.co_spent!.length === 1 ? "" : "es"} (common-input clustering).</p>}
                      {node.error && <p className="text-xs text-warning">{node.error}</p>}
                    </div>
                    {canWrite && (
                      <div className="flex flex-wrap gap-2 border-t border-line px-4 py-2.5">
                        {!node.enriched && <Button size="sm" busy={busy} onClick={() => lookup()}>Look up</Button>}
                        {node.enriched && <Button size="sm" busy={busy} onClick={() => expand(node.address)}><ArrowRight className="h-3.5 w-3.5" /> Expand</Button>}
                        <AddToCase objectType="chain" objectId={node.address} size="sm" label="Add to investigation" note={node.label} />
                        <Link href={`/search?q=${encodeURIComponent(node.address)}`}><Button size="sm"><Search className="h-3.5 w-3.5" /> Search</Button></Link>
                      </div>
                    )}
                  </Card>
                )}
                <Card className="px-4 py-3 text-xs leading-relaxed text-muted">
                  <p className="mb-1 font-semibold text-ink-2">Reading the graph</p>
                  A solid node has been looked up on-chain; a dashed node is a counterparty not yet looked up — double-click or select it, then <em>Expand</em>. Red-ringed nodes are sanctioned, mixers, or already seen in your intelligence. Amounts cover the transactions examined, newest first; a “+” means there are more.
                </Card>
              </aside>
            </div>
          </>
        )}
    </>
  );
}

export default function Page() {
  return <Suspense fallback={<Spinner />}><CryptoPage /></Suspense>;
}

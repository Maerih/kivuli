"use client";

import { forceCollide, forceLink, forceManyBody, forceSimulation, forceX, forceY, type SimulationLinkDatum, type SimulationNodeDatum } from "d3-force";
import { Maximize2, Minus, Plus, Search } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useMemo, useRef, useState, type FormEvent, type PointerEvent as ReactPointerEvent } from "react";
import { AddToCase } from "@/components/bits";
import { PageHeader } from "@/components/shell";
import { Badge, Button, Card, CardHeader, Empty, ErrorNote, Spinner } from "@/components/ui";
import { qs, useApi } from "@/lib/api";
import { cn, day, defang, ENTITY_LABELS, IOC_LABELS } from "@/lib/format";

interface GNode extends SimulationNodeDatum { id: string; group: string; label: string; count: number; seed?: boolean }
// A typed edge says how two things are related, how sure we are and who said so; an untyped one only means "seen together".
interface Typed { kind?: string; confidence?: number; provenance?: string; first_seen?: string; last_seen?: string }
interface GEdge extends SimulationLinkDatum<GNode>, Typed { weight: number; secondary?: boolean }
interface Graph { seed: string; nodes: GNode[]; edges: ({ source: string; target: string; weight: number; secondary?: boolean } & Typed)[]; groups?: string[] }
const REL: Record<string, string> = { uses: "uses", targets: "targets", attributed_to: "attributed to", exploits: "exploits", delivers: "delivers", related_to: "related to" };
const relLabel = (kind: string) => REL[kind] ?? kind.replace(/_/g, " ");

// Identity is carried by shape and label as well as colour.
const GROUPS: { match: (g: string) => boolean; label: string; color: string; shape: "circle" | "square" | "diamond" | "triangle" }[] = [
  { match: (g) => g === "actor", label: "Threat actor", color: "var(--series-2)", shape: "circle" },
  { match: (g) => g === "organization", label: "Organisation", color: "var(--series-1)", shape: "circle" },
  { match: (g) => g === "malware", label: "Malware", color: "var(--series-7)", shape: "circle" },
  { match: (g) => g === "incident" || g === "campaign", label: "Incident / campaign", color: "var(--series-3)", shape: "circle" },
  { match: (g) => g === "technique", label: "ATT&CK technique", color: "var(--series-4)", shape: "triangle" },
  { match: (g) => g.startsWith("ioc:"), label: "Indicator", color: "var(--muted)", shape: "square" },
  { match: (g) => g === "finding", label: "Finding", color: "var(--series-5)", shape: "diamond" },
];
const styleOf = (group: string) => GROUPS.find((g) => g.match(group)) ?? GROUPS[5];
const radius = (n: GNode) => (n.seed ? 15 : Math.min(13, 5 + Math.sqrt(n.count) * 1.6));
const display = (n: GNode) => (n.group.startsWith("ioc:") ? defang(n.label) : n.label);
const kindLabel = (group: string) => (group.startsWith("ioc:") ? IOC_LABELS[group.slice(4)] ?? "Indicator" : group === "finding" ? "Finding" : ENTITY_LABELS[group] ?? group);
const hrefOf = (id: string) => { const [kind, ref] = [id.slice(0, id.indexOf(":")), id.slice(id.indexOf(":") + 1)]; return kind === "entity" ? `/entities/${ref}` : kind === "ioc" ? `/indicators/${ref}` : `/findings/${ref}`; };

function layout(graph: Graph, hidden: Set<string>): { nodes: GNode[]; edges: GEdge[] } {
  const nodes: GNode[] = graph.nodes.filter((n) => n.seed || n.id === graph.seed || !hidden.has(styleOf(n.group).label)).map((n) => ({ ...n }));
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const edges: GEdge[] = graph.edges.filter((e) => byId.has(e.source) && byId.has(e.target)).map((e) => ({ ...e }));
  const simulation = forceSimulation(nodes)
    .force("link", forceLink<GNode, GEdge>(edges).id((d) => d.id).distance((e) => (e.secondary ? 150 : 115)).strength((e) => (e.secondary ? 0.05 : 0.5)))
    .force("charge", forceManyBody().strength(-420))
    .force("collide", forceCollide<GNode>().radius((d) => radius(d) + 26))
    .force("x", forceX(0).strength(0.04))
    .force("y", forceY(0).strength(0.06))
    .stop();
  for (let i = 0; i < 320; i++) simulation.tick();
  return { nodes, edges };
}

function Canvas({ graph, onExpand }: { graph: Graph; onExpand: (id: string) => void }) {
  const [hidden, setHidden] = useState<Set<string>>(new Set());
  const { nodes, edges } = useMemo(() => layout(graph, hidden), [graph, hidden]);
  const present = useMemo(() => new Set(graph.nodes.map((n) => styleOf(n.group).label)), [graph]);
  const toggleGroup = (label: string) => setHidden((h) => { const n = new Set(h); n.has(label) ? n.delete(label) : n.add(label); return n; });
  const [selected, setSelected] = useState<string>(graph.seed);
  const [hover, setHover] = useState<string | null>(null);
  const [view, setView] = useState({ x: 0, y: 0, k: 1 });
  const drag = useRef<{ x: number; y: number; vx: number; vy: number } | null>(null);
  useEffect(() => { setSelected(graph.seed); setView({ x: 0, y: 0, k: 1 }); }, [graph]);

  const bounds = useMemo(() => {
    const xs = nodes.map((n) => n.x ?? 0), ys = nodes.map((n) => n.y ?? 0);
    const pad = 90;
    const minX = Math.min(...xs) - pad, maxX = Math.max(...xs) + pad, minY = Math.min(...ys) - pad, maxY = Math.max(...ys) + pad;
    return { x: minX, y: minY, w: Math.max(maxX - minX, 400), h: Math.max(maxY - minY, 300) };
  }, [nodes]);

  const focus = hover ?? selected;
  const neighbours = useMemo(() => {
    const set = new Set<string>([focus]);
    edges.forEach((e) => { const s = (e.source as GNode).id, t = (e.target as GNode).id; if (s === focus) set.add(t); if (t === focus) set.add(s); });
    return set;
  }, [edges, focus]);
  const node = nodes.find((n) => n.id === selected);

  const onDown = (e: ReactPointerEvent<SVGSVGElement>) => { drag.current = { x: e.clientX, y: e.clientY, vx: view.x, vy: view.y }; };
  const onMove = (e: ReactPointerEvent<SVGSVGElement>) => {
    if (!drag.current) return;
    const scale = bounds.w / e.currentTarget.clientWidth / view.k;
    setView((v) => ({ ...v, x: drag.current!.vx - (e.clientX - drag.current!.x) * scale, y: drag.current!.vy - (e.clientY - drag.current!.y) * scale }));
  };
  const zoom = (factor: number) => setView((v) => ({ ...v, k: Math.min(4, Math.max(0.4, v.k * factor)) }));
  const w = bounds.w / view.k, h = bounds.h / view.k;
  const viewBox = `${bounds.x + view.x + (bounds.w - w) / 2} ${bounds.y + view.y + (bounds.h - h) / 2} ${w} ${h}`;

  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_19rem]">
      <Card className="relative overflow-hidden">
        <div className="absolute right-3 top-3 z-10 flex flex-col gap-1">
          <Button size="sm" aria-label="Zoom in" onClick={() => zoom(1.25)}><Plus className="h-3.5 w-3.5" /></Button>
          <Button size="sm" aria-label="Zoom out" onClick={() => zoom(0.8)}><Minus className="h-3.5 w-3.5" /></Button>
          <Button size="sm" aria-label="Reset view" onClick={() => setView({ x: 0, y: 0, k: 1 })}><Maximize2 className="h-3.5 w-3.5" /></Button>
        </div>
        <svg
          viewBox={viewBox} className="h-[620px] w-full cursor-grab touch-none select-none active:cursor-grabbing" role="img" aria-label="Relationship graph"
          onPointerDown={onDown} onPointerMove={onMove} onPointerUp={() => (drag.current = null)} onPointerLeave={() => (drag.current = null)}
          onWheel={(e) => zoom(e.deltaY < 0 ? 1.1 : 0.9)}
        >
          {edges.map((e, i) => {
            const s = e.source as GNode, t = e.target as GNode;
            const lit = s.id === focus || t.id === focus;
            return <line key={i} x1={s.x} y1={s.y} x2={t.x} y2={t.y} stroke={lit ? "var(--accent)" : e.kind ? "var(--ink-2)" : "var(--line-strong)"} strokeWidth={Math.min(4, 0.8 + Math.log2(1 + e.weight) * 0.7)} strokeOpacity={lit ? 0.9 : e.secondary ? 0.3 : 0.65} />;
          })}
          {edges.filter((e) => e.kind).map((e, i) => {
            const s = e.source as GNode, t = e.target as GNode;
            if (s.id !== focus && t.id !== focus && edges.length > 40) return null; // keep a busy graph readable: label only what is in focus
            return <text key={`l${i}`} x={((s.x ?? 0) + (t.x ?? 0)) / 2} y={((s.y ?? 0) + (t.y ?? 0)) / 2 - 3} textAnchor="middle" fontSize={9} fill="var(--ink-2)" stroke="var(--surface)" strokeWidth={3} paintOrder="stroke" pointerEvents="none">{relLabel(e.kind!)}</text>;
          })}
          {nodes.map((n) => {
            const st = styleOf(n.group), r = radius(n), dim = !neighbours.has(n.id);
            const text = display(n);
            return (
              <g key={n.id} transform={`translate(${n.x},${n.y})`} opacity={dim ? 0.3 : 1} className="cursor-pointer"
                onPointerDown={(e) => e.stopPropagation()} onClick={() => setSelected(n.id)} onDoubleClick={() => onExpand(n.id)} onMouseEnter={() => setHover(n.id)} onMouseLeave={() => setHover(null)}>
                <title>{`${kindLabel(n.group)}: ${text}`}</title>
                {st.shape === "circle" && <circle r={r} fill={st.color} stroke="var(--surface)" strokeWidth={2} />}
                {st.shape === "square" && <rect x={-r * 0.8} y={-r * 0.8} width={r * 1.6} height={r * 1.6} rx={2} fill={st.color} stroke="var(--surface)" strokeWidth={2} />}
                {st.shape === "diamond" && <rect x={-r * 0.8} y={-r * 0.8} width={r * 1.6} height={r * 1.6} rx={2} transform="rotate(45)" fill={st.color} stroke="var(--surface)" strokeWidth={2} />}
                {st.shape === "triangle" && <polygon points={`0,${-r * 1.1} ${r},${r * 0.8} ${-r},${r * 0.8}`} fill={st.color} stroke="var(--surface)" strokeWidth={2} strokeLinejoin="round" />}
                {(n.seed || n.id === selected) && <circle r={r + 5} fill="none" stroke="var(--accent)" strokeWidth={2} />}
                <text y={r + 14} textAnchor="middle" fontSize={11} fontWeight={n.seed ? 700 : 500} fill="var(--ink)" stroke="var(--surface)" strokeWidth={3} paintOrder="stroke" className={n.group.startsWith("ioc:") ? "font-mono" : ""}>
                  {text.length > 26 ? `${text.slice(0, 25)}…` : text}
                </text>
              </g>
            );
          })}
        </svg>
        <div className="flex flex-wrap gap-x-4 gap-y-1 border-t border-line px-4 py-2 text-xs text-ink-2">
          {GROUPS.filter((g) => present.has(g.label)).map((g) => (
            <button key={g.label} onClick={() => toggleGroup(g.label)} aria-pressed={!hidden.has(g.label)} title={hidden.has(g.label) ? `Show ${g.label.toLowerCase()} nodes` : `Hide ${g.label.toLowerCase()} nodes`}
              className={cn("inline-flex items-center gap-1.5 rounded px-1 hover:bg-sunken", hidden.has(g.label) && "text-muted line-through opacity-60")}>
              {g.shape === "triangle" ? <span className="h-0 w-0 border-x-[5px] border-b-[9px] border-x-transparent" style={{ borderBottomColor: g.color }} />
                : <span className={cn("h-2.5 w-2.5", g.shape === "circle" ? "rounded-full" : "rounded-sm", g.shape === "diamond" && "rotate-45")} style={{ background: g.color }} />}{g.label}
            </button>
          ))}
          <span className="ml-auto text-muted">Labelled lines are stated relationships, plain lines mean “seen together” · click a type to hide it · double-click a node to re-centre</span>
        </div>
      </Card>

      <Card className="h-fit">
        {node ? (
          <div className="px-4 py-3">
            <div className="label">{kindLabel(node.group)}</div>
            <div className={cn("mt-1 break-all text-base font-semibold", node.group.startsWith("ioc:") && "font-mono text-sm")}>{display(node)}</div>
            <p className="mt-1 text-xs text-muted">{node.seed ? `${node.count} findings in total` : node.count > 0 ? `${node.count} finding${node.count === 1 ? "" : "s"} in common with the centre` : "Linked by a stated relationship, not yet seen together in a finding"}</p>
            <div className="mt-3 flex flex-wrap gap-2">
              <Link href={hrefOf(node.id)}><Button size="sm">Open details</Button></Link>
              {!node.seed && <Button size="sm" variant="primary" onClick={() => onExpand(node.id)}>Centre graph here</Button>}
              <AddToCase objectType="graph" objectId={node.id} note={`${kindLabel(node.group)}: ${display(node)}`} size="sm" label="Bookmark to case" />
            </div>
            <div className="label mt-4">Connected to</div>
            <ul className="mt-1 max-h-72 space-y-0.5 overflow-y-auto scroll-thin text-sm">
              {edges.filter((e) => (e.source as GNode).id === node.id || (e.target as GNode).id === node.id)
                .map((e) => ({ other: (e.source as GNode).id === node.id ? (e.target as GNode) : (e.source as GNode), outgoing: (e.source as GNode).id === node.id, e }))
                .sort((a, b) => Number(Boolean(b.e.kind)) - Number(Boolean(a.e.kind)) || b.e.weight - a.e.weight).map(({ other, outgoing, e }) => (
                  <li key={other.id + (e.kind ?? "")}><button onClick={() => setSelected(other.id)} className="w-full rounded px-1.5 py-1 text-left hover:bg-sunken">
                    <span className="flex items-center justify-between gap-2"><span className="truncate">{display(other)}</span><span className="shrink-0 text-xs tabular-nums text-muted">{e.kind ? "" : e.weight}</span></span>
                    {e.kind && <span className="mt-0.5 flex flex-wrap items-center gap-1 text-2xs text-muted" title={`${e.provenance ?? ""}${e.first_seen ? ` · first recorded ${day(e.first_seen)}` : ""}${e.last_seen ? ` · last ${day(e.last_seen)}` : ""}`}>
                      <Badge tone="accent">{outgoing ? relLabel(e.kind) : `${relLabel(e.kind)} (inbound)`}</Badge>{e.confidence !== undefined && <span>{e.confidence}% confidence</span>}{e.provenance && <span className="truncate">· {e.provenance}</span>}</span>}
                  </button></li>
                ))}
            </ul>
          </div>
        ) : <Empty title="Select a node" />}
      </Card>
    </div>
  );
}

interface PathNode { id: string; kind: string; type: string; label: string; findings: number; href: string }
interface PathHop { via: "finding" | "relationship" | "unknown"; id?: string; title?: string; date?: string | null; source?: string; label?: string }
interface PathResult { from: PathNode; to: PathNode; paths: { length: number; nodes: PathNode[]; hops: PathHop[] }[]; expanded: number; max_hops: number; note: string }

/** How the item on screen connects to another: the shortest chains of findings and stated relationships. */
function PathFinder({ from }: { from: string }) {
  const params = useSearchParams();
  const router = useRouter();
  const to = params.get("to");
  const [q, setQ] = useState("");
  const [term, setTerm] = useState("");
  const { data: found } = useApi<{ items: { id: number; type: string; name: string; doc_count: number }[] }>(term ? `/entities${qs({ q: term, sort: "frequent", size: 8 })}` : null);
  const { data, error, isLoading } = useApi<PathResult>(to ? `/graph/path${qs({ from, to })}` : null);
  const pick = (target: string) => { setTerm(""); setQ(""); router.replace(`/graph${qs({ node: from, to: target })}`); };
  return (
    <Card className="mt-4">
      <CardHeader title="Find a connection" hint={`The shortest chains (up to ${data?.max_hops ?? 4} steps) linking this item to another, through findings and stated relationships. Common techniques, platforms and very common entities are not used as steps.`} />
      <div className="px-4 py-3">
        <form onSubmit={(e) => { e.preventDefault(); setTerm(q.trim()); }} className="relative max-w-xl">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
          <input className="field pl-9" placeholder="Connect to an actor, organisation or malware family…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Connect to" />
        </form>
        {term && found && (
          <div className="mt-2 flex flex-wrap items-center gap-1.5">
            <span className="text-xs text-muted">{found.items.length ? "Connect to" : "No matching entities"}</span>
            {found.items.filter((e) => e.type !== "incident" && `entity:${e.id}` !== from).map((e) => (
              <button key={e.id} onClick={() => pick(`entity:${e.id}`)} className="rounded-full border border-line-strong bg-raised px-2.5 py-0.5 text-xs hover:border-accent hover:text-accent-ink">
                {e.name} <span className="text-muted">{e.doc_count}</span>
              </button>
            ))}
          </div>
        )}
        <ErrorNote error={error} />
        {to && isLoading && <div className="mt-3"><Spinner label="Searching for connections" /></div>}
        {data && (
          <div className="mt-3 space-y-3">
            <p className="text-sm">
              <Link className="font-medium hover:underline" href={data.from.href}>{data.from.label}</Link> <span className="text-muted">to</span>{" "}
              <Link className="font-medium hover:underline" href={data.to.href}>{data.to.label}</Link>
              <span className="text-xs text-muted"> · {data.paths.length ? `${data.paths.length} shortest path${data.paths.length > 1 ? "s" : ""}, ${data.paths[0].length} step${data.paths[0].length > 1 ? "s" : ""}` : "no path"}</span>
            </p>
            {data.paths.length === 0 && <p className="text-sm text-muted">{data.note}</p>}
            {data.paths.map((p, i) => (
              <ol key={i} className="rounded-md border border-line px-3 py-2 text-sm">
                {p.nodes.map((n, j) => (
                  <li key={n.id + j}>
                    <div className="flex items-center gap-2 py-0.5">
                      <Link href={n.href} className="font-medium hover:underline">{n.label}</Link>
                      <span className="text-2xs text-muted">{ENTITY_LABELS[n.type] ?? IOC_LABELS[n.type] ?? n.type}</span>
                      <button className="ml-auto text-2xs text-accent-ink hover:underline" onClick={() => router.push(`/graph${qs({ node: n.id })}`)}>Explore</button>
                    </div>
                    {p.hops[j] && (
                      <div className="ml-2 border-l-2 border-line py-1 pl-3 text-xs text-ink-2">
                        {p.hops[j].via === "finding" ? <>both in <Link href={`/findings/${p.hops[j].id}`} className="text-accent-ink hover:underline">{p.hops[j].title}</Link>{p.hops[j].date ? ` · ${day(p.hops[j].date)}` : ""} · {p.hops[j].source}</>
                          : p.hops[j].via === "relationship" ? <>stated: <span className="font-medium">{p.hops[j].label}</span> ({p.hops[j].source})</> : "linked"}
                      </div>
                    )}
                  </li>
                ))}
              </ol>
            ))}
          </div>
        )}
      </div>
    </Card>
  );
}

function GraphPage() {
  const params = useSearchParams();
  const router = useRouter();
  const node = params.get("node");
  const { data, error, isLoading } = useApi<Graph>(node ? `/graph?node=${encodeURIComponent(node)}` : null, { keepPreviousData: true });
  const [q, setQ] = useState("");
  const [term, setTerm] = useState("");
  const { data: found } = useApi<{ items: { id: number; type: string; name: string; doc_count: number }[] }>(term ? `/entities${qs({ q: term, sort: "frequent", size: 8 })}` : null);
  const { data: starters } = useApi<{ items: { id: number; type: string; name: string; doc_count: number }[] }>(!node ? "/entities?type=actor&sort=frequent&size=10" : null);
  const expand = (id: string) => router.push(`/graph?node=${encodeURIComponent(id)}`);
  const submit = (e: FormEvent) => { e.preventDefault(); setTerm(q.trim()); };
  const list = term ? found?.items : starters?.items;

  return (
    <>
      <PageHeader title="Relationships" subtitle="See how actors, victims, malware, techniques and indicators connect. A labelled link is a stated relationship with a confidence and a source; a plain link means the two appear in the same findings." />
      <form onSubmit={submit} className="relative mb-4 max-w-xl">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
        <input className="field pl-9" placeholder="Find an actor, organisation or malware family to explore" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Find an entity" />
      </form>
      {(term || !node) && list && (
        <div className="mb-4 flex flex-wrap items-center gap-1.5">
          <span className="text-xs text-muted">{term ? (list.length ? "Matches" : "No matching entities") : "Start with"}</span>
          {list.filter((e) => e.type !== "incident").map((e) => (
            <button key={e.id} onClick={() => { setTerm(""); setQ(""); expand(`entity:${e.id}`); }} className="rounded-full border border-line-strong bg-raised px-2.5 py-0.5 text-xs hover:border-accent hover:text-accent-ink">
              {e.name} <span className="text-muted">{e.doc_count}</span>
            </button>
          ))}
        </div>
      )}
      <ErrorNote error={error} />
      {!node ? <Card><Empty title="Pick a starting point" hint="Choose an entity above, or open the relationship view from any finding, indicator or entity page." /></Card>
        : !data && isLoading ? <Spinner label="Building graph" />
        : data && data.nodes.length <= 1 ? <Card><Empty title="No relationships yet" hint="Nothing else has been seen alongside this item so far." /></Card>
        : data ? <div className={cn(isLoading && "opacity-60")}><Canvas graph={data} onExpand={expand} /></div> : null}
      {node && /^(entity|ioc):\d+$/.test(node) && <PathFinder from={node} />}
    </>
  );
}

export default function Page() {
  return <Suspense fallback={<Spinner />}><GraphPage /></Suspense>;
}

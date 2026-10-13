"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { PageHeader } from "@/components/shell";
import { Card, ErrorNote, Spinner } from "@/components/ui";
import { useApi } from "@/lib/api";
import { cn, num } from "@/lib/format";

interface Cell { id: string; name: string; count: number; actors: number }
interface Matrix { version: string; days: number; observed: number; tactics: { id: string; shortname: string; name: string; techniques: Cell[] }[] }

// One hue, four steps: how often a technique shows up in collected intelligence. The count is always printed too.
const STEPS = [14, 30, 55, 100];
function shade(level: number): React.CSSProperties {
  if (level === 0) return {};
  const mix = STEPS[level - 1];
  return { background: `color-mix(in srgb, var(--accent) ${mix}%, var(--raised))`, color: mix === 100 ? "var(--on-accent)" : undefined, borderColor: "transparent" };
}

export default function AttackPage() {
  const [days, setDays] = useState(90);
  const [all, setAll] = useState(false);
  const { data, error, isLoading } = useApi<Matrix>(`/attack/matrix?days=${days}`, { keepPreviousData: true });
  const max = useMemo(() => Math.max(1, ...(data?.tactics.flatMap((t) => t.techniques.map((c) => c.count)) ?? [1])), [data]);
  const level = (count: number) => (count <= 0 ? 0 : Math.max(1, Math.min(4, Math.ceil((4 * Math.log(count + 1)) / Math.log(max + 1)))));
  const showAll = all || (data?.observed ?? 0) === 0;

  return (
    <>
      <PageHeader
        title="ATT&CK coverage"
        subtitle="Which adversary techniques appear in the intelligence you have collected, laid out on the MITRE ATT&CK Enterprise matrix. A technique is tagged when a finding names its ID or clearly describes the behaviour."
        actions={<>
          <label className="flex items-center gap-2 text-xs text-ink-2">Period
            <select className="field h-8 w-auto px-2 text-xs" value={days} onChange={(e) => setDays(Number(e.target.value))}>
              <option value={30}>Last 30 days</option><option value={90}>Last 90 days</option><option value={365}>Last year</option><option value={3650}>All time</option>
            </select>
          </label>
          <label className="flex cursor-pointer items-center gap-1.5 text-xs text-ink-2"><input type="checkbox" className="accent-[var(--accent)]" checked={showAll} disabled={(data?.observed ?? 0) === 0} onChange={(e) => setAll(e.target.checked)} /> Show every technique</label>
        </>}
      />
      <ErrorNote error={error} />
      {!data ? <Spinner /> : (
        <>
          <div className="mb-3 flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-muted">
            <span><span className="font-semibold text-ink">{num(data.observed)}</span> technique{data.observed === 1 ? "" : "s"} observed in this period</span>
            <span className="inline-flex items-center gap-1.5">Fewer
              {STEPS.map((_, i) => <span key={i} className="h-3 w-5 rounded-sm border border-line" style={shade(i + 1)} />)}
              more findings</span>
            <span>The small figure is how many tracked groups are known to use the technique.</span>
            <span className="ml-auto">ATT&amp;CK v{data.version}</span>
          </div>
          <Card className={cn("scroll-thin overflow-x-auto p-3", isLoading && "opacity-60")}>
            <div className="grid min-w-max auto-cols-[10.5rem] grid-flow-col gap-2">
              {data.tactics.map((tactic) => {
                const cells = showAll ? tactic.techniques : tactic.techniques.filter((c) => c.count > 0);
                const seen = tactic.techniques.filter((c) => c.count > 0).length;
                return (
                  <section key={tactic.id} aria-label={tactic.name}>
                    <header className="mb-2 border-b-2 border-line-strong pb-1.5">
                      <Link href={`/search?q=${encodeURIComponent(`tactic:${tactic.shortname}`)}`} className="block truncate text-xs font-semibold hover:text-accent-ink hover:underline" title={`Search findings tagged ${tactic.name}`}>{tactic.name}</Link>
                      <div className="text-2xs text-muted">{seen} of {tactic.techniques.length} seen</div>
                    </header>
                    <ul className="space-y-1">
                      {cells.length === 0 && <li className="rounded border border-dashed border-line px-2 py-1.5 text-2xs text-muted">Nothing observed</li>}
                      {cells.map((c) => (
                        <li key={c.id}>
                          <Link href={`/attack/${c.id}`} style={shade(level(c.count))} title={`${c.id} ${c.name}: ${c.count} finding${c.count === 1 ? "" : "s"}, used by ${c.actors} tracked group${c.actors === 1 ? "" : "s"}`}
                            className="flex items-start justify-between gap-1.5 rounded border border-line px-2 py-1.5 text-2xs leading-snug hover:outline hover:outline-2 hover:outline-accent">
                            <span className="min-w-0"><span className="block font-mono opacity-70">{c.id}</span><span className="line-clamp-2 font-medium">{c.name}</span></span>
                            <span className="shrink-0 text-right tabular-nums"><span className="block text-xs font-semibold">{c.count || ""}</span>{c.actors > 0 && <span className="opacity-70">{c.actors}g</span>}</span>
                          </Link>
                        </li>
                      ))}
                    </ul>
                  </section>
                );
              })}
            </div>
          </Card>
          <p className="mt-3 text-xs text-muted">Sub-techniques are counted under their parent. MITRE ATT&amp;CK® is a registered trademark of The MITRE Corporation; the catalogue is reproduced under the ATT&amp;CK terms of use.</p>
        </>
      )}
    </>
  );
}

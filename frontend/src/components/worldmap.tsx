"use client";

import { geoEqualEarth, geoPath } from "d3-geo";
import { useRouter } from "next/navigation";
import { useEffect, useMemo, useRef, useState } from "react";
import { feature } from "topojson-client";
import type { GeometryCollection, Topology } from "topojson-specification";
import world from "world-atlas/countries-110m.json";
import { num } from "@/lib/format";

export interface CountryCount { value: string; label?: string; count: number; numeric?: string }

const WIDTH = 960;
const HEIGHT = 440;
// One hue, light to dark, mixed against the surface so it reads in both themes.
const STEPS = [32, 48, 64, 80, 96];

/** Countries shaded by how many findings name them. Hover for the count; click to open those findings. */
export function WorldMap({ data, caption }: { data: CountryCount[]; caption: string }) {
  const router = useRouter();
  const box = useRef<HTMLDivElement>(null);
  const [hover, setHover] = useState<{ x: number; y: number; name: string; count: number } | null>(null);

  const shapes = useMemo(() => {
    const topo = world as unknown as Topology<{ countries: GeometryCollection<{ name: string }> }>;
    const countries = feature(topo, topo.objects.countries).features.filter((f) => f.id !== "010"); // no Antarctica
    const projection = geoEqualEarth().fitExtent([[4, 4], [WIDTH - 4, HEIGHT - 4]], { type: "FeatureCollection", features: countries });
    const path = geoPath(projection);
    return countries.map((f) => ({ id: String(f.id ?? ""), name: f.properties?.name ?? "", d: path(f) ?? "" }));
  }, []);

  const byNumeric = useMemo(() => new Map(data.filter((d) => d.numeric).map((d) => [d.numeric as string, d])), [data]);
  const max = Math.max(1, ...data.map((d) => d.count));
  // Log scale: a few countries dominate, and a linear scale would leave the rest blank.
  const step = (count: number) => Math.min(STEPS.length - 1, Math.floor((Math.log1p(count) / Math.log1p(max)) * STEPS.length));
  const fill = (count: number) => `color-mix(in oklab, var(--series-1) ${STEPS[step(count)]}%, var(--sunken))`;
  const bounds = STEPS.map((_, i) => Math.max(1, Math.round(Math.expm1((Math.log1p(max) * i) / STEPS.length))));

  useEffect(() => setHover(null), [data]);

  const move = (e: React.PointerEvent, name: string, count: number) => {
    const rect = box.current?.getBoundingClientRect();
    if (rect) setHover({ x: e.clientX - rect.left, y: e.clientY - rect.top, name, count });
  };

  return (
    <figure className="m-0">
      <div ref={box} className="relative" onPointerLeave={() => setHover(null)}>
        <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} className="block h-auto w-full" role="img" aria-label={caption}>
          {shapes.map((s) => {
            const hit = byNumeric.get(s.id);
            const name = hit?.label ?? s.name;
            return (
              <path
                key={s.id + s.name}
                d={s.d}
                fill={hit ? fill(hit.count) : "var(--sunken)"}
                stroke="var(--surface)"
                strokeWidth={0.6}
                className={hit ? "cursor-pointer transition-opacity hover:opacity-80" : undefined}
                onPointerMove={(e) => move(e, name, hit?.count ?? 0)}
                onClick={hit ? () => router.push(`/search?country=${hit.value}`) : undefined}
              >
                <title>{`${name}: ${hit ? num(hit.count) : "no"} finding${hit?.count === 1 ? "" : "s"}`}</title>
              </path>
            );
          })}
        </svg>
        {hover && (
          <div className="pointer-events-none absolute z-10 whitespace-nowrap rounded-md border border-line bg-raised px-2.5 py-1.5 text-xs shadow-md"
               style={{ left: Math.min(hover.x + 12, (box.current?.clientWidth ?? 0) - 160), top: hover.y + 12 }}>
            <div className="font-medium text-ink">{hover.name}</div>
            <div className="tabular-nums text-ink-2">{hover.count ? `${num(hover.count)} finding${hover.count === 1 ? "" : "s"}` : "No findings"}</div>
          </div>
        )}
      </div>
      <figcaption className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-2xs text-muted">
        <span>Findings naming the country</span>
        <span className="flex items-center gap-1"><span className="inline-block h-2.5 w-4 rounded-sm border border-line" style={{ background: "var(--sunken)" }} /> none</span>
        {STEPS.map((pct, i) => (
          <span key={pct} className="flex items-center gap-1 tabular-nums">
            <span className="inline-block h-2.5 w-4 rounded-sm" style={{ background: `color-mix(in oklab, var(--series-1) ${pct}%, var(--sunken))` }} />
            {i === STEPS.length - 1 ? `${num(bounds[i])}+` : `${num(bounds[i])}`}
          </span>
        ))}
      </figcaption>
    </figure>
  );
}

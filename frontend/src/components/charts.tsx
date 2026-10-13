"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { cn, num } from "@/lib/format";

function useWidth<T extends HTMLElement>() {
  const ref = useRef<T>(null);
  const [width, setWidth] = useState(0);
  useEffect(() => {
    if (!ref.current) return;
    const observer = new ResizeObserver(([entry]) => setWidth(Math.floor(entry.contentRect.width)));
    observer.observe(ref.current);
    return () => observer.disconnect();
  }, []);
  return [ref, width] as const;
}

function niceCeil(max: number): { top: number; ticks: number[] } {
  if (max <= 4) return { top: 4, ticks: [0, 2, 4] };
  const magnitude = 10 ** Math.floor(Math.log10(max));
  const step = [1, 2, 2.5, 5, 10].map((m) => (m * magnitude) / 2).find((s) => max / s <= 4) ?? magnitude * 5;
  const top = Math.ceil(max / step) * step;
  const ticks: number[] = [];
  for (let t = 0; t <= top + 1e-9; t += step) ticks.push(Math.round(t));
  return { top, ticks };
}

export interface Series { name: string; color: string }
export interface ColumnDatum { label: string; values: number[] }

/** Stacked columns over time. Thin marks, 2px surface gaps, rounded data-ends, hover tooltip. */
export function ColumnChart({ data, series, height = 200, caption }: { data: ColumnDatum[]; series: Series[]; height?: number; caption: string }) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const [hover, setHover] = useState<number | null>(null);
  const pad = { top: 10, right: 8, bottom: 22, left: 36 };
  const innerW = Math.max(0, width - pad.left - pad.right);
  const innerH = height - pad.top - pad.bottom;
  const totals = data.map((d) => d.values.reduce((a, b) => a + b, 0));
  const { top, ticks } = niceCeil(Math.max(1, ...totals));
  const band = data.length ? innerW / data.length : 0;
  const barW = Math.max(2, Math.min(24, band - 2));
  const y = (v: number) => pad.top + innerH - (v / top) * innerH;
  const labelEvery = Math.max(1, Math.ceil(data.length / Math.max(2, Math.floor(innerW / 70))));
  const active = hover !== null ? data[hover] : null;

  return (
    <figure className="relative" ref={ref}>
      {series.length > 1 && (
        <figcaption className="mb-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-ink-2">
          {series.map((s) => (
            <span key={s.name} className="inline-flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-sm" style={{ background: s.color }} />{s.name}</span>
          ))}
        </figcaption>
      )}
      {width > 0 && (
        <svg width={width} height={height} role="img" aria-label={caption} onMouseLeave={() => setHover(null)}>
          {ticks.map((t) => (
            <g key={t}>
              <line x1={pad.left} x2={width - pad.right} y1={y(t)} y2={y(t)} stroke={t === 0 ? "var(--axis)" : "var(--grid)"} strokeWidth={1} />
              <text x={pad.left - 6} y={y(t)} dy="0.32em" textAnchor="end" fontSize={10.5} fill="var(--muted)" style={{ fontVariantNumeric: "tabular-nums" }}>{num(t)}</text>
            </g>
          ))}
          {data.map((d, i) => {
            const cx = pad.left + band * i + band / 2;
            let acc = 0;
            const lastFilled = d.values.reduce((last, v, k) => (v > 0 ? k : last), -1);
            return (
              <g key={i} opacity={hover === null || hover === i ? 1 : 0.45}>
                {d.values.map((v, k) => {
                  if (v <= 0) return null;
                  const y0 = y(acc);
                  acc += v;
                  const y1 = y(acc);
                  // A 2px gap in the surface colour separates stacked segments.
                  const h = Math.max(1, y0 - y1 - (k > 0 ? 2 : 0));
                  const yTop = y0 - (k > 0 ? 2 : 0) - h;
                  const r = k === lastFilled ? Math.min(4, barW / 2, h) : 0;
                  const x = cx - barW / 2;
                  return <path key={k} fill={series[k].color} d={`M${x},${yTop + h}V${yTop + r}a${r},${r} 0 0 1 ${r},${-r}h${barW - 2 * r}a${r},${r} 0 0 1 ${r},${r}V${yTop + h}Z`} />;
                })}
                {i % labelEvery === 0 && <text x={cx} y={height - 6} textAnchor="middle" fontSize={10.5} fill="var(--muted)">{d.label}</text>}
                <rect x={pad.left + band * i} y={pad.top} width={band} height={innerH} fill="transparent" onMouseEnter={() => setHover(i)} />
              </g>
            );
          })}
        </svg>
      )}
      {active && hover !== null && (
        <div
          className="pointer-events-none absolute z-10 min-w-36 rounded-md bg-raised px-2.5 py-2 text-xs shadow-pop"
          style={{ left: Math.min(Math.max(0, pad.left + band * hover + band / 2 - 72), Math.max(0, width - 150)), top: 0 }}
        >
          <div className="mb-1 font-semibold text-ink">{active.label}</div>
          {series.map((s, k) => (
            <div key={s.name} className="flex items-center justify-between gap-4 text-ink-2">
              <span className="inline-flex items-center gap-1.5"><span className="h-2 w-2 rounded-sm" style={{ background: s.color }} />{s.name}</span>
              <span className="tabular-nums text-ink">{num(active.values[k])}</span>
            </div>
          ))}
        </div>
      )}
      <table className="sr-only">
        <caption>{caption}</caption>
        <thead><tr><th>Period</th>{series.map((s) => <th key={s.name}>{s.name}</th>)}</tr></thead>
        <tbody>{data.map((d) => <tr key={d.label}><td>{d.label}</td>{d.values.map((v, k) => <td key={k}>{v}</td>)}</tr>)}</tbody>
      </table>
    </figure>
  );
}

export interface BarItem { key: string; label: string; value: number; href?: string; hint?: string }

/** Ranked horizontal bars: one hue, label and value above a thin full-width bar; the whole row is the hit target. */
export function BarList({ items, color = "var(--series-1)", empty = "No data yet" }: { items: BarItem[]; color?: string; empty?: string }) {
  const max = Math.max(1, ...items.map((i) => i.value));
  if (!items.length) return <p className="py-6 text-center text-sm text-muted">{empty}</p>;
  return (
    <ul className="space-y-0.5">
      {items.map((item) => {
        const row = (
          <div className="group rounded px-1.5 py-1.5 hover:bg-sunken" title={item.hint ?? `${item.label}: ${num(item.value)}`}>
            <div className="flex items-baseline justify-between gap-3">
              <span className="truncate text-sm text-ink-2 group-hover:text-ink">{item.label}</span>
              <span className="shrink-0 text-sm tabular-nums text-ink">{num(item.value)}</span>
            </div>
            <div className="mt-1 h-1.5">
              <div className="h-full rounded-r" style={{ width: `${Math.max(1.5, (item.value / max) * 100)}%`, background: color }} />
            </div>
          </div>
        );
        return <li key={item.key}>{item.href ? <Link href={item.href}>{row}</Link> : row}</li>;
      })}
    </ul>
  );
}

/** Small single-series column strip for inline trends. */
export function MiniColumns({ values, labels, height = 44, caption }: { values: number[]; labels?: string[]; height?: number; caption: string }) {
  const max = Math.max(1, ...values);
  const [hover, setHover] = useState<number | null>(null);
  return (
    <div className="relative" role="img" aria-label={caption}>
      <div className="flex items-end gap-0.5" style={{ height }} onMouseLeave={() => setHover(null)}>
        {values.map((v, i) => (
          <div key={i} className="flex h-full flex-1 items-end" onMouseEnter={() => setHover(i)}>
            <div className={cn("w-full rounded-t-sm", v === 0 && "opacity-30")} style={{ height: `${Math.max(v ? 6 : 2, (v / max) * 100)}%`, background: "var(--series-1)", opacity: hover === null || hover === i ? undefined : 0.45 }} />
          </div>
        ))}
      </div>
      {hover !== null && (
        <div className="pointer-events-none absolute -top-7 right-0 rounded bg-raised px-2 py-1 text-xs shadow-pop">
          <span className="text-muted">{labels?.[hover] ?? ""}</span> <span className="tabular-nums text-ink">{num(values[hover])}</span>
        </div>
      )}
    </div>
  );
}

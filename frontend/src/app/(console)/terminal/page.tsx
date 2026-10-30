"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { useSession } from "@/components/session";
import { PageHeader } from "@/components/shell";
import { Button, Tabs } from "@/components/ui";
import { api, useApi } from "@/lib/api";
import { defang, num } from "@/lib/format";

/*
 * Kivuli's command line. Every command is a call to the same API the rest of
 * the console uses, with your session: it can do exactly what your role can,
 * it is audited the same way, and it never runs anything on the server's shell.
 */

type Line =
  | { kind: "cmd"; text: string }
  | { kind: "out"; text: string; tone?: "muted" | "error" | "good" | "warn" }
  | { kind: "rows"; head: string[]; rows: ReactNode[][] }
  | { kind: "node"; node: ReactNode };

type Ctx = { print: (l: Line) => void; out: (text: string, tone?: "muted" | "error" | "good" | "warn") => void; go: (path: string) => void };
type Command = { usage: string; help: string; run: (args: string[], ctx: Ctx) => Promise<void> };

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const q = encodeURIComponent;
const link = (href: string, text: ReactNode) => <Link href={href} className="text-accent-ink hover:underline">{text}</Link>;

/** Split like a shell: spaces separate, quotes group. */
function parse(line: string): string[] {
  const out: string[] = [];
  let cur = "", quote: string | null = null, has = false;
  for (const ch of line) {
    if (quote) { if (ch === quote) quote = null; else cur += ch; continue; }
    if (ch === '"' || ch === "'") { quote = ch; has = true; continue; }
    if (/\s/.test(ch)) { if (cur || has) { out.push(cur); cur = ""; has = false; } continue; }
    cur += ch;
  }
  if (cur || has) out.push(cur);
  return out;
}

const PAGES: Record<string, string> = {
  home: "/", search: "/search", findings: "/findings", alerts: "/alerts", watchlists: "/watchlists", sources: "/sources", collection: "/collection",
  crawls: "/crawls", cases: "/cases", entities: "/entities", indicators: "/indicators", graph: "/graph", timeline: "/timeline", crypto: "/crypto",
  tools: "/tools", attack: "/attack", trends: "/trends", exposures: "/exposures", vulnerabilities: "/vulnerabilities", integrations: "/integrations", settings: "/settings",
};

const COMMANDS: Record<string, Command> = {
  search: {
    usage: "search <query>", help: "Search everything collected (all operators work, e.g. actor:qilin country:KE last:7d)",
    run: async (args, { print, out }) => {
      if (!args.length) return out("usage: search <query>", "error");
      const query = args.join(" ");
      const r = await api<{ total: number; hits: { id: string; title: string; severity: string; source_name: string; network: string; date?: string; first_seen?: string }[] }>(`/search?q=${q(query)}&size=10`);
      out(`${num(r.total)} findings`, "muted");
      print({ kind: "rows", head: ["Severity", "Finding", "Source"], rows: r.hits.map((h) => [h.severity, link(`/findings/${h.id}`, h.title.slice(0, 90)), `${h.source_name}${h.network === "onion" ? " (Tor)" : ""}`]) });
      if (r.total > 10) print({ kind: "node", node: link(`/search?q=${q(query)}`, "Open all results →") });
    },
  },
  verdict: {
    usage: "verdict <indicator>", help: "Everything known about an IP, domain, URL, hash, email, wallet, CVE or handle",
    run: async (args, { print, out }) => {
      if (!args[0]) return out("usage: verdict <indicator>", "error");
      let queued = false;
      try { queued = (await api<{ queued: boolean }>("/tools/verdict", { method: "POST", body: { value: args[0] } })).queued; } catch { /* viewers: read only */ }
      type V = { verdict: string; type: string; value: string; reasons: string[]; results: { label: string; ok: boolean; verdict: string }[]; wallet: { balance: number | null; token: string; tx_count: number | null } | null };
      let v = await api<V>(`/tools/verdict?value=${q(args[0])}`);
      if (queued) { out("asking providers…", "muted"); for (let i = 0; i < 4; i++) { await sleep(2500); v = await api<V>(`/tools/verdict?value=${q(args[0])}`); } }
      out(`${v.verdict.toUpperCase()}  ${v.type}  ${defang(v.value)}`, v.verdict === "malicious" ? "error" : v.verdict === "suspicious" ? "warn" : v.verdict === "clean" ? "good" : undefined);
      v.reasons.forEach((r) => out(`  • ${r}`));
      if (v.results.length) print({ kind: "rows", head: ["Provider", "Answer"], rows: v.results.map((r) => [r.label, r.ok ? r.verdict : "no answer"]) });
      if (v.wallet?.balance !== undefined && v.wallet?.balance !== null) out(`  on-chain: ${v.wallet.balance} ${v.wallet.token}, ${v.wallet.tx_count ?? "?"} transactions`);
      print({ kind: "node", node: link(`/tools?tool=verdict&value=${q(v.value)}`, "Open in Tools →") });
    },
  },
  trace: {
    usage: "trace <wallet>", help: "Read a Bitcoin, Ethereum or TRON wallet on-chain and open its flow graph",
    run: async (args, { out, go }) => {
      if (!args[0]) return out("usage: trace <wallet>", "error");
      const r = await api<{ address: string; supported: boolean }>("/chain/lookup", { method: "POST", body: { address: args[0] } });
      out(r.supported ? "looking it up on-chain; opening the tracer…" : "recognised, but this chain cannot be read on-chain; opening what is known…", "muted");
      go(`/crypto?address=${q(r.address)}`);
    },
  },
  decode: {
    usage: "decode <text>", help: "Peel encodings off a payload (quote it). Nothing is run",
    run: async (args, { print, out }) => {
      if (!args.length) return out('usage: decode "<payload>"', "error");
      const r = await api<{ ok: boolean; error?: string; layers: { step: string }[]; final: string; behaviours: { label: string; evidence: string[] }[]; indicators: { type: string; value: string }[] }>("/tools/decode", { method: "POST", body: { text: args.join(" ") } });
      if (!r.ok) return out(r.error ?? "could not decode", "error");
      out(r.layers.slice(1).map((l) => l.step).join(" → ") || "no encoding found", "muted");
      print({ kind: "node", node: <pre className="whitespace-pre-wrap break-all text-ink">{r.final.slice(0, 4000)}</pre> });
      r.behaviours.forEach((b) => out(`  ! ${b.label}: ${b.evidence.join(", ")}`, "warn"));
      r.indicators.slice(0, 20).forEach((i) => out(`  ${i.type}: ${defang(i.value)}`));
    },
  },
  actor: {
    usage: "actor <name>", help: "A threat actor's profile: claims, tempo, where it posts, what it targets",
    run: async (args, { print, out }) => {
      if (!args.length) return out("usage: actor <name>", "error");
      const list = await api<{ items: { id: number; name: string; aliases: string[]; doc_count: number }[] }>(`/entities?q=${q(args.join(" "))}&type=actor`);
      const a = list.items[0];
      if (!a) return out("no actor by that name", "error");
      type P = { claims: number; last_30_days: number; median_gap_days: number | null; last: string | null; weekdays: { day: string; count: number }[]; sites: { name: string; findings: number }[];
        monthly: { month: string; claims: number; top_sectors: string[]; top_countries: { name: string }[] }[] };
      const p = await api<P>(`/entities/${a.id}/patterns`);
      print({ kind: "node", node: <span className="font-semibold text-ink">{link(`/entities/${a.id}`, a.name)}{a.aliases.length ? <span className="font-normal text-muted"> aka {a.aliases.join(", ")}</span> : null}</span> });
      out(`${num(a.doc_count)} findings · ${num(p.claims)} claims · ${num(p.last_30_days)} in the last 30 days · typical gap ${p.median_gap_days ?? "—"} days`);
      const busiest = [...p.weekdays].sort((x, y) => y.count - x.count)[0];
      if (busiest?.count) out(`busiest day: ${busiest.day} · posts on: ${p.sites.map((s) => s.name).slice(0, 3).join(", ")}`, "muted");
      if (p.monthly.length) print({ kind: "rows", head: ["Month", "Claims", "Sectors", "Countries"], rows: [...p.monthly].reverse().slice(0, 6).map((m) => [m.month, num(m.claims), m.top_sectors.join(", "), m.top_countries.map((c) => c.name).join(", ")]) });
    },
  },
  sources: {
    usage: "sources [text]", help: "List sources, optionally matching text",
    run: async (args, { print }) => {
      const r = await api<{ items: { id: number; name: string; status: string; state: string; network: string; doc_count: number; last_error: string }[] }>(`/sources?q=${q(args.join(" "))}`);
      print({ kind: "rows", head: ["Id", "Source", "Status", "State", "Findings"], rows: r.items.slice(0, 25).map((s) => [String(s.id), link(`/sources/${s.id}`, s.name.slice(0, 60)), s.status, s.state, num(s.doc_count)]) });
    },
  },
  source: {
    usage: "source <id> check|crawl|monitor|pause|js-on|js-off", help: "Act on one source",
    run: async ([id, action], { out }) => {
      if (!id || !/^\d+$/.test(id) || !action) return out("usage: source <id> check|crawl|monitor|pause|js-on|js-off", "error");
      const patch = (body: object) => api(`/sources/${id}`, { method: "PATCH", body });
      const acts: Record<string, () => Promise<unknown>> = {
        check: () => api(`/sources/${id}/verify`, { method: "POST" }), crawl: () => api(`/sources/${id}/crawl`, { method: "POST" }),
        monitor: () => patch({ status: "approved" }), pause: () => patch({ status: "paused" }), "js-on": () => patch({ render_js: true }), "js-off": () => patch({ render_js: false }),
      };
      if (!acts[action]) return out(`unknown action: ${action}`, "error");
      await acts[action]();
      out(`source ${id}: ${action} done`, "good");
    },
  },
  crawl: {
    usage: "crawl <url> [depth] [pages]", help: "Start a research crawl of one site (onion or web), staying on that site",
    run: async ([url, depth, pages], { print, out }) => {
      if (!url) return out("usage: crawl <url> [depth] [pages]", "error");
      const r = await api<{ id: number; source: { name: string } }>("/crawls", { method: "POST", body: { url, depth: Number(depth ?? 1), max_pages: Number(pages ?? 50) } });
      print({ kind: "node", node: <span>Crawl {r.id} started on {r.source.name}. {link(`/crawls/${r.id}`, "Follow it →")}</span> });
    },
  },
  watch: {
    usage: "watch <kind> <value> [name]", help: "Add a watchlist (kind: keyword, domain, email, ip, organization, actor, cve, hash, crypto, username, brand…)",
    run: async ([kind, value, ...name], { out }) => {
      if (!kind || !value) return out("usage: watch <kind> <value> [name]", "error");
      await api("/watchlists", { method: "POST", body: { kind, value, name: name.join(" ") || `${kind}: ${value}` } });
      out(`watching ${kind} ${value}`, "good");
    },
  },
  alerts: {
    usage: "alerts", help: "Open alerts, highest priority first",
    run: async (_a, { print, out }) => {
      const r = await api<{ total: number; items: { id: number; severity: string; matched: string; reason: string; created_at: string }[] }>("/alerts?status=open&size=15");
      out(`${num(r.total)} open`, "muted");
      print({ kind: "rows", head: ["Severity", "Matched", "Why"], rows: r.items.map((a) => [a.severity, link("/alerts", a.matched.slice(0, 60)), a.reason.slice(0, 80)]) });
    },
  },
  timeline: {
    usage: "timeline [days]", help: "Who was active, and what connects the events",
    run: async ([days], { print, out }) => {
      const r = await api<{ events: unknown[]; lanes: { name: string; count: number }[]; links: { kind: string }[]; possible_aliases: { a: { name: string }; b: { name: string }; shared_victims: number }[] }>(`/timeline?days=${Number(days ?? 30)}`);
      const kinds = r.links.reduce<Record<string, number>>((acc, l) => ({ ...acc, [l.kind]: (acc[l.kind] ?? 0) + 1 }), {});
      out(`${num(r.events.length)} events · links: ${Object.entries(kinds).map(([k, n]) => `${n} ${k}`).join(", ") || "none"}`, "muted");
      print({ kind: "rows", head: ["Actor", "Events"], rows: r.lanes.slice(0, 10).map((l) => [l.name, num(l.count)]) });
      r.possible_aliases.forEach((p) => out(`  possibly the same actor: ${p.a.name} / ${p.b.name} (${p.shared_victims} shared victims)`, "warn"));
    },
  },
  stats: {
    usage: "stats [days]", help: "Headline numbers for a period",
    run: async ([days], { out }) => {
      const d = await api<{ total: number; in_window: number; last_24h: number; with_credentials: number; open_alerts: { total: number }; sources?: { approved: number } }>(`/dashboard?days=${Number(days ?? 30)}`);
      out(`${num(d.total)} findings in all · ${num(d.in_window)} in the period · ${num(d.last_24h)} in the last 24 h · ${num(d.with_credentials)} with credentials · ${num(d.open_alerts.total)} open alerts`);
    },
  },
  providers: {
    usage: "providers", help: "Enrichment providers and whether each is on",
    run: async (_a, { print }) => {
      const r = await api<{ providers: { label: string; tier: string; enabled: boolean; key_rejected?: string; blocked_hosts: string[] }[] }>("/providers");
      print({ kind: "rows", head: ["Provider", "Tier", "State"], rows: r.providers.filter((p) => p.tier !== "planned").map((p) => [p.label, p.tier, p.key_rejected ? "key rejected" : p.blocked_hosts.length ? "host not allowed" : p.enabled ? "on" : "off"]) });
    },
  },
  open: {
    usage: "open <page>", help: `Go to a page: ${Object.keys(PAGES).join(", ")}`,
    run: async ([page], { out, go }) => {
      if (!page || !PAGES[page]) return out(`pages: ${Object.keys(PAGES).join(", ")}`, "error");
      go(PAGES[page]);
    },
  },
};

const BUILTINS = ["help", "clear", "history"];
const HISTORY_KEY = "kivuli:terminal:history";

function loadHistory(): string[] {
  try { return JSON.parse(localStorage.getItem(HISTORY_KEY) ?? "[]"); } catch { return []; }
}

interface ShellStatus { enabled: boolean; allowed: boolean; reason: string; open: boolean; grant_hours: number; ssh_host: string; ssh_port: number }

/** A browser SSH terminal to the VPS itself (WeTTY behind Caddy, gated by Kivuli). Asks for the server's SSH login every session. */
function ServerShell() {
  const { data, error, mutate } = useApi<ShellStatus>("/shell/status");
  const [frame, setFrame] = useState(0);
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState("");
  const act = async (path: string, show: boolean) => {
    setBusy(true); setProblem("");
    try { await api(path, { method: "POST" }); setFrame(show ? Date.now() : 0); await mutate(); }
    catch (e) { setProblem(e instanceof Error ? e.message : "failed"); }
    finally { setBusy(false); }
  };
  if (error) return <p className="text-sm text-critical">{error.status === 403 ? "Only administrators can open the server shell." : error.message}</p>;
  if (!data) return <p className="text-sm text-muted">Checking…</p>;
  if (!data.allowed) {
    return (
      <div className="rounded-lg border border-line bg-[var(--raised)] px-4 py-4 text-sm">
        <p className="font-medium text-ink">The server shell is not available.</p>
        <p className="mt-1 text-ink-2">{data.reason}</p>
        <p className="mt-3 text-xs text-muted">On the server: <code>./ctl.sh https &lt;domain&gt; &lt;email&gt;</code>, then <code>./ctl.sh shell on</code>. It logs in to this server's own SSH with the username and password you type, every session.</p>
      </div>
    );
  }
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        {frame ? <Button busy={busy} onClick={() => act("/shell/close", false)}>Close the shell</Button>
          : <Button variant="primary" busy={busy} onClick={() => act("/shell/open", true)}>Open server shell</Button>}
        <span className="text-xs text-muted">SSH to {data.ssh_host}:{data.ssh_port}. Opening is recorded in the audit log; access lasts {data.grant_hours} hours unless closed.</span>
      </div>
      {problem && <p className="text-sm text-critical">{problem}</p>}
      {frame ? <iframe key={frame} src="/shell/" title="Server shell" className="h-[66vh] w-full rounded-lg border border-line bg-black" /> : null}
    </div>
  );
}

export default function TerminalPage() {
  const { isAdmin } = useSession();
  const [tab, setTab] = useState<"kivuli" | "server">("kivuli");
  const router = useRouter();
  const [lines, setLines] = useState<Line[]>([{ kind: "out", text: "Kivuli command line. Type help for the commands; Tab completes, ↑ ↓ walk your history.", tone: "muted" }]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [history, setHistory] = useState<string[]>([]);
  const [cursor, setCursor] = useState(-1);
  const end = useRef<HTMLDivElement>(null);
  const box = useRef<HTMLInputElement>(null);

  useEffect(() => { setHistory(loadHistory()); box.current?.focus(); }, []);
  useEffect(() => { end.current?.scrollIntoView({ block: "end" }); }, [lines]);

  const print = (l: Line) => setLines((ls) => [...ls, l]);
  const out = (text: string, tone?: "muted" | "error" | "good" | "warn") => print({ kind: "out", text, tone });

  const run = async (raw: string) => {
    const text = raw.trim();
    if (!text) return;
    print({ kind: "cmd", text });
    const next = [...history.filter((h) => h !== text), text].slice(-200);
    setHistory(next);
    try { localStorage.setItem(HISTORY_KEY, JSON.stringify(next)); } catch { /* private window */ }
    setCursor(-1);
    const [name, ...args] = parse(text);
    if (name === "clear") return setLines([]);
    if (name === "history") return next.slice(-20).forEach((h, i) => out(`${String(i + 1).padStart(3)}  ${h}`, "muted"));
    if (name === "help" || name === "?") {
      print({ kind: "rows", head: ["Command", "What it does"], rows: [...Object.values(COMMANDS).map((c) => [<code key={c.usage}>{c.usage}</code>, c.help]), [<code key="b">clear · history · help</code>, "Clear the screen, show recent commands, this list"]] });
      return;
    }
    const cmd = COMMANDS[name];
    if (!cmd) return out(`unknown command: ${name}. Type help.`, "error");
    setBusy(true);
    try {
      await cmd.run(args, { print, out, go: (p) => router.push(p) });
    } catch (e) {
      out(e instanceof Error ? e.message : "failed", "error");
    } finally {
      setBusy(false);
      setTimeout(() => box.current?.focus(), 0);
    }
  };

  const onKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" && !busy) { run(input); setInput(""); }
    else if (e.key === "ArrowUp" && history.length) {
      e.preventDefault();
      const i = cursor < 0 ? history.length - 1 : Math.max(0, cursor - 1);
      setCursor(i); setInput(history[i]);
    } else if (e.key === "ArrowDown" && cursor >= 0) {
      e.preventDefault();
      const i = cursor + 1;
      if (i >= history.length) { setCursor(-1); setInput(""); } else { setCursor(i); setInput(history[i]); }
    } else if (e.key === "Tab") {
      e.preventDefault();
      const [word, ...rest] = input.split(" ");
      if (rest.length) return;
      const names = [...Object.keys(COMMANDS), ...BUILTINS].filter((n) => n.startsWith(word));
      if (names.length === 1) setInput(`${names[0]} `);
      else if (names.length > 1) out(names.join("  "), "muted");
    } else if (e.key === "l" && e.ctrlKey) { e.preventDefault(); setLines([]); }
  };

  const tone = { muted: "text-muted", error: "text-critical", good: "text-good", warn: "text-warning" } as const;
  return (
    <>
      <PageHeader title="Command line" subtitle="Kivuli's commands, or a shell on the server itself for administrators." />
      {isAdmin && <div className="mb-3"><Tabs<"kivuli" | "server"> tabs={[{ id: "kivuli", label: "Kivuli commands" }, { id: "server", label: "Server shell" }]} value={tab} onChange={setTab} /></div>}
      {tab === "server" ? <ServerShell /> : <div className="rounded-lg border border-line bg-[var(--raised)] font-mono text-[13px] leading-relaxed" onClick={() => box.current?.focus()}>
        <div className="scroll-thin h-[62vh] overflow-y-auto px-4 py-3" aria-live="polite">
          {lines.map((l, i) => (
            <div key={i} className="min-w-0">
              {l.kind === "cmd" && <div className="mt-2 text-ink"><span className="select-none text-accent-ink">kivuli ›</span> {l.text}</div>}
              {l.kind === "out" && <div className={`whitespace-pre-wrap break-words ${l.tone ? tone[l.tone] : "text-ink-2"}`}>{l.text}</div>}
              {l.kind === "node" && <div className="text-ink-2">{l.node}</div>}
              {l.kind === "rows" && (
                <div className="scroll-thin my-1 overflow-x-auto">
                  <table className="text-left">
                    <thead><tr>{l.head.map((h) => <th key={h} className="pr-5 font-normal text-muted">{h}</th>)}</tr></thead>
                    <tbody>{l.rows.map((r, j) => <tr key={j}>{r.map((c, k) => <td key={k} className="max-w-[36rem] truncate pr-5 align-top text-ink-2">{c}</td>)}</tr>)}</tbody>
                  </table>
                  {l.rows.length === 0 && <div className="text-muted">nothing</div>}
                </div>
              )}
            </div>
          ))}
          <div ref={end} />
        </div>
        <label className="flex items-center gap-2 border-t border-line px-4 py-2.5">
          <span className="select-none text-accent-ink">kivuli ›</span>
          <input ref={box} value={input} onChange={(e) => setInput(e.target.value)} onKeyDown={onKey} disabled={busy} spellCheck={false} autoComplete="off"
                 aria-label="Command" placeholder={busy ? "working…" : "type a command, e.g. verdict 185.220.101.4"} className="min-w-0 flex-1 bg-transparent text-ink outline-none placeholder:text-muted" />
        </label>
      </div>}
    </>
  );
}

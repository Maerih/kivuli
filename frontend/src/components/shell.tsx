"use client";

import {
  Activity, Bell, Briefcase, Bug, CalendarRange, ChartColumn, Coins, Crosshair, Fingerprint, Grid3x3, KeyRound, LayoutDashboard, LogOut, Menu, Moon, Plug, Radar, Scan, Search, Settings, Share2, ShieldCheck, Siren, SquareTerminal, Sun, Users, Wrench, X,
} from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { api, useApi } from "@/lib/api";
import { cn } from "@/lib/format";
import { useSession } from "./session";

const NAV = [
  { group: "Research", items: [
    { href: "/", label: "Command centre", icon: LayoutDashboard },
    { href: "/search", label: "Dark-web search", icon: Search },
    { href: "/terminal", label: "Command line", icon: SquareTerminal },
    { href: "/sources", label: "Source explorer", icon: Radar },
    { href: "/collection", label: "Collection & crawls", icon: Activity },
    { href: "/cases", label: "Investigations", icon: Briefcase },
  ] },
  { group: "Monitoring", items: [
    { href: "/alerts", label: "Alerts", icon: Bell, badge: true },
    { href: "/watchlists", label: "Watchlists", icon: Crosshair },
    { href: "/rules", label: "Detection rules", icon: Siren },
  ] },
  { group: "Intelligence", items: [
    { href: "/entities", label: "Actors & entities", icon: Users },
    { href: "/indicators", label: "Indicators", icon: Fingerprint },
    { href: "/graph", label: "Relationships", icon: Share2 },
    { href: "/timeline", label: "Event timeline", icon: CalendarRange },
    { href: "/crypto", label: "Crypto tracer", icon: Coins },
    { href: "/tools", label: "Tools", icon: Wrench },
    { href: "/attack", label: "ATT&CK", icon: Grid3x3 },
  ] },
  { group: "Exposure", items: [
    { href: "/exposures", label: "Identity exposure", icon: KeyRound },
    { href: "/attack-surface", label: "Attack surface", icon: Scan },
    { href: "/vulnerabilities", label: "Vulnerabilities", icon: Bug },
  ] },
  { group: "Platform", items: [
    { href: "/trends", label: "Trends", icon: ChartColumn },
    { href: "/integrations", label: "Integrations", icon: Plug },
    { href: "/settings", label: "System", icon: Settings },
  ] },
];

function ThemeToggle() {
  const [dark, setDark] = useState(false);
  useEffect(() => {
    const stored = document.documentElement.dataset.theme;
    setDark(stored ? stored === "dark" : window.matchMedia("(prefers-color-scheme: dark)").matches);
  }, []);
  const toggle = () => {
    const next = dark ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem("kivuli-theme", next); } catch { /* private mode */ }
    setDark(!dark);
  };
  return (
    <button onClick={toggle} aria-label={dark ? "Switch to light theme" : "Switch to dark theme"} title="Toggle theme" className="rounded-md p-2 text-ink-2 hover:bg-sunken hover:text-ink">
      {dark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
    </button>
  );
}

export function Shell({ children }: { children: ReactNode }) {
  const { me, meta } = useSession();
  const pathname = usePathname();
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const { data: alerts } = useApi<{ by_status: Record<string, number> }>("/alerts?size=1", { refreshInterval: 60000 });
  const openAlerts = alerts?.by_status?.open ?? 0;

  useEffect(() => setOpen(false), [pathname]);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (query.trim()) router.push(`/search?q=${encodeURIComponent(query.trim())}`);
    setQuery("");
  };
  const signOut = async () => {
    await api("/auth/logout", { method: "POST" }).catch(() => {});
    window.location.href = "/login";
  };
  const isActive = (href: string) => (href === "/" ? pathname === "/" : pathname === href || pathname.startsWith(href + "/"));

  return (
    <div className="min-h-screen lg:pl-60">
      <aside className={cn("fixed inset-y-0 left-0 z-40 flex w-60 flex-col border-r border-line bg-surface transition-transform lg:translate-x-0", open ? "translate-x-0" : "-translate-x-full")}>
        <div className="flex h-14 items-center gap-2.5 border-b border-line px-4">
          <span className="flex h-7 w-7 items-center justify-center rounded-md bg-ink text-page"><ShieldCheck className="h-4 w-4" /></span>
          <div className="min-w-0 leading-tight">
            <div className="truncate text-sm font-semibold">{meta.app_name}</div>
            <div className="truncate text-2xs text-muted">Dark-web research workstation</div>
          </div>
          <button className="ml-auto rounded p-1 text-muted lg:hidden" onClick={() => setOpen(false)} aria-label="Close menu"><X className="h-4 w-4" /></button>
        </div>
        <nav className="scroll-thin flex-1 overflow-y-auto px-2 py-3">
          {NAV.map((section) => (
            <div key={section.group} className="mb-4">
              <div className="label px-2 pb-1.5">{section.group}</div>
              {section.items.map((item) => (
                <Link key={item.href} href={item.href} aria-current={isActive(item.href) ? "page" : undefined}
                  className={cn("flex items-center gap-2.5 rounded-md px-2 py-1.5 text-sm", isActive(item.href) ? "bg-accent-soft font-medium text-accent-ink" : "text-ink-2 hover:bg-sunken hover:text-ink")}>
                  <item.icon className="h-4 w-4 shrink-0" />
                  <span className="truncate">{item.label}</span>
                  {"badge" in item && openAlerts > 0 && <span className="ml-auto rounded-full bg-critical px-1.5 text-2xs font-semibold tabular-nums text-white">{openAlerts > 999 ? "999+" : openAlerts}</span>}
                </Link>
              ))}
            </div>
          ))}
        </nav>
        <div className="border-t border-line p-3">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-sunken text-xs font-semibold uppercase text-ink-2">{(me.name || me.email).slice(0, 2)}</div>
            <div className="min-w-0 flex-1 leading-tight">
              <div className="truncate text-sm font-medium">{me.name || me.email}</div>
              <div className="truncate text-2xs capitalize text-muted">{me.role}</div>
            </div>
            <button onClick={signOut} title="Sign out" aria-label="Sign out" className="rounded-md p-2 text-ink-2 hover:bg-sunken hover:text-ink"><LogOut className="h-4 w-4" /></button>
          </div>
        </div>
      </aside>
      {open && <div className="fixed inset-0 z-30 bg-black/40 lg:hidden" onClick={() => setOpen(false)} />}

      <header className="sticky top-0 z-20 flex h-14 items-center gap-3 border-b border-line bg-surface px-4">
        <button className="rounded-md p-2 text-ink-2 hover:bg-sunken lg:hidden" onClick={() => setOpen(true)} aria-label="Open menu"><Menu className="h-4 w-4" /></button>
        {pathname !== "/search" && pathname !== "/" && (
          <form onSubmit={submit} className="relative max-w-xl flex-1">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
            <input value={query} onChange={(e) => setQuery(e.target.value)} className="field pl-9" placeholder="Search findings, domains, emails, actors, CVEs…" aria-label="Search" />
          </form>
        )}
        <div className="ml-auto flex items-center gap-1"><ThemeToggle /></div>
      </header>
      <main className="mx-auto w-full max-w-[1500px] px-4 py-5 sm:px-6">{children}</main>
    </div>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: ReactNode; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-start justify-between gap-3">
      <div className="min-w-0">
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        {subtitle && <p className="mt-1 max-w-3xl text-sm text-muted">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

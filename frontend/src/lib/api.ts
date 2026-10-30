"use client";

import useSWR, { type SWRConfiguration } from "swr";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

function detail(body: unknown, fallback: string): string {
  if (body && typeof body === "object" && "detail" in body) {
    const d = (body as { detail: unknown }).detail;
    if (typeof d === "string") return d;
    if (Array.isArray(d) && d[0]?.msg) return `${d[0].loc?.slice(-1)[0] ?? "field"}: ${d[0].msg}`;
  }
  return fallback;
}

/** Call the API. Every request carries the CSRF header the server requires. */
export async function api<T = unknown>(path: string, init: { method?: string; body?: unknown } = {}): Promise<T> {
  const res = await fetch(`/api${path}`, {
    method: init.method ?? "GET",
    credentials: "same-origin",
    headers: { "X-Kivuli-CSRF": "1", ...(init.body !== undefined ? { "Content-Type": "application/json" } : {}) },
    body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
  });
  if (res.status === 401 && typeof window !== "undefined" && !window.location.pathname.startsWith("/login")) {
    window.location.href = `/login?next=${encodeURIComponent(window.location.pathname + window.location.search)}`;
  }
  const body = await res.json().catch(() => null);
  if (!res.ok) throw new ApiError(res.status, detail(body, `Request failed (${res.status})`));
  return body as T;
}

export function useApi<T = any>(path: string | null, config?: SWRConfiguration) {
  return useSWR<T, ApiError>(path, (p: string) => api<T>(p), { revalidateOnFocus: false, shouldRetryOnError: false, ...config });
}

export function qs(params: Record<string, string | number | boolean | undefined | null | string[]>): string {
  const sp = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "" || value === false) continue;
    if (Array.isArray(value)) value.forEach((v) => sp.append(key, v));
    else sp.set(key, String(value));
  }
  const out = sp.toString();
  return out ? `?${out}` : "";
}

export type Role = "viewer" | "analyst" | "admin";
export interface Me { id: number; email: string; name: string; role: Role; mfa_enabled?: boolean; mfa_setup_required?: boolean }
export interface Bucket { value: string; count: number; label?: string }
export interface Part { t: string; h: boolean }

export interface Meta {
  app_name: string;
  threat_types: Record<string, string>;
  countries: Record<string, string>;
  focus_countries: string[];
  severities: string[];
  finding_statuses: string[];
  alert_statuses: string[];
  watch_kinds: string[];
  entity_types: string[];
  ioc_types: string[];
  connectors: Record<string, string>;
  operators: { op: string; help: string; example: string }[];
  redaction: boolean;
  verification: Record<string, string>;
  reliability: Record<string, string>;
  credibility: Record<string, string>;
  tactics: { shortname: string; name: string }[];
  attack_version: string;
  techniques: Record<string, string>;
  rule_kinds: string[];
  focus_sectors: string[];
  languages: Record<string, string>;
  source_categories: string[];
}

export interface SourceBrief {
  id: number; name: string; title: string; host: string; network: string; category: string; status: string; state: "online" | "degraded" | "offline" | "unknown";
  doc_count: number; relevance: number; created_at: string; last_live_at: string | null; discovery_context: string;
}
export interface CrawlProgress { fetched: number; ok: number; failed: number; new: number; changed: number; deepest: number; queued: number; discovered: number; last_activity: string | null }
export interface CrawlJob {
  id: number; url: string; depth: number; max_pages: number; status: "running" | "done" | "stopped" | "failed"; note: string; case_id: number | null;
  created_at: string; finished_at: string | null; created_by: string; progress: CrawlProgress;
  source: { id: number; name: string; host: string; network: string; status: string };
}
export interface CollectionStatus {
  tor: { online: boolean; exit_ip: string; latency_ms: number | null; checked_at: string | null; error: string };
  collectors: { online: number; expected: number; roles: Record<string, number> };
  sources: { active: number; active_onion: number; candidates: number; candidates_onion: number; offline: number; blocked: number; states: Record<string, Record<string, number>> };
  queue: { crawl: number; pipeline: number; enrich: number };
  pages: { indexed: number; onion: number; new_24h: number };
  last_collection: string | null; fetches_24h: number; failed_24h: number; crawls_running: number;
  blocklist: { count: number; updated_at: string | null };
  policy: { auto_approve: string; relevance_threshold: number; max_onion_sources: number; discovery_groups_per_run: number; research_max_depth: number; research_max_pages: number };
}

export interface Factor { factor: string; points: number }

export interface FindingSummary {
  id: string; title: string; summary: string; url: string; host: string; network: string; source_id: number; source_name: string;
  threat_type: string; threat_label: string; severity: string; risk_score: number; confidence: number; countries: string[];
  has_credentials: boolean; status: string; first_seen: string; last_seen: string; published_at: string | null; version_count: number;
  verification?: string;
}

export interface Hit {
  id: string; score: number | null; title: string; title_parts: Part[]; snippets: Part[][]; url: string; host: string;
  source_name: string; source_category: string; network: string; threat_type: string; threat_types: string[]; severity: string;
  risk_score: number; confidence: number; countries: string[]; sectors: string[]; actors: string[]; organizations: string[];
  malware: string[]; tags: string[]; status: string; has_credentials: boolean; credential_count: number; ioc_count: number;
  is_duplicate: boolean; version_count: number; date: string; first_seen: string; last_seen: string; last_changed: string;
  techniques?: string[]; verification?: string; corroboration?: number; admiralty?: string;
  relevance?: number | null; why?: { kind: string; label: string }[]; lang?: string; seen_at?: number; source_id?: number;
}

export interface SearchResult {
  query: string; total: number; took_ms: number; page: number; size: number; sort: string; hits: Hit[];
  facets: Record<string, Bucket[]>;
  timeline: { interval: string; buckets: { date: string; count: number }[] };
  summary: { with_credentials: number; avg_risk: number; max_risk: number };
  interpretation: { kind: string; label: string; detail: string }[];
  did_you_mean: string | null;
  sources?: { id: number; count: number; latest: string | null; name: string; category: string; network: string; host: string }[];
}


export interface ChainNode {
  address: string; chain: string; enriched: boolean; category: string; category_label: string; label: string;
  balance: number | null; token: string; total_in?: number; total_out?: number; tx_count: number | null;
  counterparty_count?: number; truncated?: boolean; in_intel: boolean; co_spent?: string[]; first_tx?: string | null;
  last_tx?: string | null; risk: boolean; error?: string; defanged: string;
}
export interface ChainEdge { src: string; dst: string; value: number; tx_count: number; sample_txid: string; first_seen: string | null; last_seen: string | null }
export interface ChainGraph {
  address: string; chain: string; chain_label: string; can_look_up: boolean; enriched: boolean; root: ChainNode;
  nodes: ChainNode[]; edges: ChainEdge[]; findings: FindingSummary[]; note: string;
}

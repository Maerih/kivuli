export function cn(...parts: (string | false | null | undefined)[]): string {
  return parts.filter(Boolean).join(" ");
}

const RTF = new Intl.RelativeTimeFormat("en", { numeric: "auto" });

export function ago(iso?: string | null): string {
  if (!iso) return "never";
  const seconds = (new Date(iso).getTime() - Date.now()) / 1000;
  const abs = Math.abs(seconds);
  if (abs < 60) return "just now";
  if (abs < 3600) return RTF.format(Math.round(seconds / 60), "minute");
  if (abs < 86400) return RTF.format(Math.round(seconds / 3600), "hour");
  if (abs < 86400 * 30) return RTF.format(Math.round(seconds / 86400), "day");
  if (abs < 86400 * 365) return RTF.format(Math.round(seconds / (86400 * 30)), "month");
  return RTF.format(Math.round(seconds / (86400 * 365)), "year");
}

export function day(iso?: string | null): string {
  return iso ? new Date(iso).toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" }) : "";
}

export function stamp(iso?: string | null): string {
  if (!iso) return "";
  return new Date(iso).toLocaleString("en-GB", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", timeZone: "UTC" }) + " UTC";
}

export function compact(n: number): string {
  if (n < 1000) return String(n);
  if (n < 10000) return (n / 1000).toFixed(1).replace(/\.0$/, "") + "K";
  if (n < 1_000_000) return Math.round(n / 1000) + "K";
  return (n / 1_000_000).toFixed(1).replace(/\.0$/, "") + "M";
}

export function num(n: number): string {
  return n.toLocaleString("en-US");
}

/** Make an indicator safe to display and copy: nothing here should be clickable. */
export function defang(value: string): string {
  return value.replace(/^http/i, "hxxp").replace(/:\/\//g, "[://]").replace(/\./g, "[.]").replace(/@/g, "[@]");
}

export function titleCase(value: string): string {
  return value.replace(/_/g, " ").replace(/^\w/, (c) => c.toUpperCase());
}

export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

export const IOC_LABELS: Record<string, string> = {
  domain: "Domain", onion: "Onion address", url: "URL", ip: "IP address", email: "Email", hash: "File hash", cve: "CVE",
  crypto: "Crypto wallet", username: "Username",
};

export const ENTITY_LABELS: Record<string, string> = {
  actor: "Threat actor", organization: "Organisation", malware: "Malware", campaign: "Campaign", incident: "Incident", technique: "Technique",
};

export const WATCH_LABELS: Record<string, { label: string; hint: string; placeholder: string }> = {
  keyword: { label: "Keyword or phrase", hint: "Whole-word match in titles and content.", placeholder: "Kenya Power" },
  domain: { label: "Domain", hint: "The domain, every subdomain, and any mailbox under it.", placeholder: "example.co.ke" },
  email: { label: "Email address", hint: "Alerts when this exact address appears, and whether a password was exposed with it.", placeholder: "ceo@example.co.ke" },
  ip: { label: "IP or CIDR range", hint: "A single address or a network block you own.", placeholder: "41.90.64.0/20" },
  organization: { label: "Organisation", hint: "Named as a victim or mentioned in text.", placeholder: "Kenya Airways" },
  actor: { label: "Threat actor", hint: "A group or alias you track.", placeholder: "LockBit" },
  cve: { label: "CVE", hint: "A vulnerability identifier.", placeholder: "CVE-2024-3400" },
  hash: { label: "File hash", hint: "MD5, SHA-1 or SHA-256.", placeholder: "44d88612fea8a8f36de82e1278abb02f" },
  crypto: { label: "Crypto wallet", hint: "A Bitcoin, Ethereum or Monero address.", placeholder: "bc1q…" },
  username: { label: "Username", hint: "A handle used on forums or Telegram.", placeholder: "threat_handle" },
  brand: { label: "Brand", hint: "Mentions of the brand, plus look-alike domains that imitate it.", placeholder: "Safaricom" },
  technology: { label: "Technology in use", hint: "A product you run. Alerts on vulnerability and exploitation reports that name it.", placeholder: "FortiGate" },
  vendor: { label: "Vendor or supplier", hint: "A third party you depend on, named as a victim or in a breach.", placeholder: "Acme Payroll Ltd" },
  executive: { label: "Executive or VIP", hint: "A person's full name appearing in leaks or threats.", placeholder: "Jane Wanjiru" },
};

export const EXPOSURE_LABELS: Record<string, string> = {
  credential: "Leaked credential", stealer_log: "Infostealer log", api_key: "API key", token: "Access token", private_key: "Private key", cloud_secret: "Cloud secret", card: "Payment card",
};

const SECRET_LABELS: Record<string, string> = {
  aws_access_key: "AWS access key", github_token: "GitHub token", gitlab_token: "GitLab token", slack_token: "Slack token", google_api_key: "Google API key",
  stripe_live_key: "Stripe live key", github_fine_grained_token: "GitHub fine-grained token", sendgrid_key: "SendGrid key", azure_storage_key: "Azure storage key", jwt: "JSON Web Token", private_key: "Private key",
};
/** "aws_access_key" -> "AWS access key" */
export function secretLabel(type: string): string {
  return SECRET_LABELS[type] ?? titleCase(type || "secret");
}

export const VERDICT_TONE: Record<string, "critical" | "warning" | "good" | "neutral"> = { malicious: "critical", suspicious: "warning", clean: "good", unknown: "neutral" };

/** 0.9432 -> "94.3%" */
export function pct(value: number | null | undefined, digits = 1): string {
  return value === null || value === undefined ? "n/a" : `${(value * 100).toFixed(digits).replace(/\.0$/, "")}%`;
}

export const SOURCE_KIND_LABELS: Record<string, string> = {
  ransomware_leak_site: "Leak site", forum: "Forum", marketplace: "Marketplace", paste: "Paste site", tracker: "Tracker feed", news: "News",
  vuln_feed: "Vulnerability feed", blog: "Blog", other: "Other",
};

/** A long onion address, shortened for display without losing its start and end. */
export function shortHost(host: string): string {
  return host.length > 34 ? `${host.slice(0, 16)}…${host.slice(-12)}` : host;
}

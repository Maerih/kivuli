"""Runtime configuration.

Every container gets only the variables its role needs (see docker-compose.yml):
the crawler, for example, never receives database or signing secrets. Fields
therefore default to empty and each role checks what it requires at start-up.
"""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    app_name: str = "Kivuli"
    role: str = "api"  # api | pipeline | notify | crawler | enricher | beat | egress
    public_url: str = "http://localhost:3000"

    # Data plane (api, pipeline, notify)
    database_url: str = ""
    opensearch_url: str = "http://search:9200"
    opensearch_user: str = ""
    opensearch_password: str = ""
    opensearch_index: str = "kivuli-findings"

    # Queue (everything except the search node and the databases)
    redis_url: str = "redis://redis:6379/0"

    # API
    jwt_secret: str = ""
    session_ttl_minutes: int = 480
    cookie_secure: bool = False  # set true when served over HTTPS
    rate_limit_per_minute: int = 300
    login_rate_limit_per_minute: int = 10
    bootstrap_admin_email: str = ""
    bootstrap_admin_password: str = ""

    # Evidence
    evidence_hmac_key: str = ""
    evidence_store_raw: bool = False
    evidence_dir: str = "/evidence"
    redact_secrets: bool = True

    # Crawler
    tor_socks_url: str = "socks5h://tor:9050"
    egress_proxy_url: str = "http://egress:8888"
    render_url: str = "http://render:9300"
    render_timeout_seconds: int = 90
    tor_user_agent: str = "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0"
    direct_user_agent: str = "Kivuli-TI/1.0 (defensive threat-intelligence collection)"
    crawl_max_bytes: int = 2_000_000
    crawl_timeout_seconds: int = 75
    crawl_host_delay_seconds: float = 3.0
    crawl_max_redirects: int = 3

    # Egress proxy (clearnet allowlist)
    egress_allow_hosts: str = ""

    # Collection policy (pipeline)
    focus_countries: str = "KE"
    discover_onion_links: bool = True
    max_candidates_per_crawl: int = 25
    liveness_interval_hours: int = 12

    # Email alerts (notify)
    email_enabled: bool = True
    smtp_host: str = "mailpit"
    smtp_port: int = 1025
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_tls: str = "none"  # none | starttls | ssl
    smtp_from: str = "Kivuli Alerts <alerts@kivuli.local>"
    alert_email_to: str = ""  # default recipients, comma separated
    digest_hour_utc: int = 6
    email_max_alerts_per_message: int = 25

    # ── Release 1.1 ──────────────────────────────────────────────────────────
    # Encrypts integration credentials and MFA secrets at rest (api, notify).
    secrets_key: str = ""
    # Encrypts provider API keys entered in the console. Held by the API (to store them) and the enricher (to use them) only.
    provider_keys_key: str = ""
    require_mfa: bool = False  # refuse password-only sign-in for admins
    focus_sectors: str = ""  # comma separated, e.g. "Financial Services,Government"
    integrations_allow_private: bool = False  # let webhooks target private addresses (an internal SIEM)

    # Enrichment and AI (enricher role only; every call leaves through the egress proxy).
    virustotal_api_key: str = ""
    shodan_api_key: str = ""
    abuseipdb_api_key: str = ""
    greynoise_api_key: str = ""
    nvd_api_key: str = ""
    dwi_api_key: str = ""
    dwi_base_url: str = "https://api.darkwebinformer.com"
    anthropic_api_key: str = ""
    ai_model: str = "claude-opus-5-5"
    asm_max_hosts: int = 300
    asm_interval_days: int = 7

    @property
    def focus_sector_list(self) -> list[str]:
        return [s.strip().lower() for s in self.focus_sectors.split(",") if s.strip()]

    @property
    def focus_country_list(self) -> list[str]:
        return [c.strip().upper() for c in self.focus_countries.split(",") if c.strip()]

    @property
    def default_recipients(self) -> list[str]:
        return [a.strip() for a in self.alert_email_to.split(",") if a.strip()]

    @property
    def egress_allow_list(self) -> list[str]:
        return [h.strip().lower() for h in self.egress_allow_hosts.split(",") if h.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()

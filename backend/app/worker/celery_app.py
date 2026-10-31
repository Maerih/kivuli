"""Celery application shared by every worker role.

Three queues, three trust levels:
  crawl     crawler container  - talks to Tor and the egress proxy, holds no secrets
  enrich    enricher container - third-party lookups and AI through the egress proxy; holds provider keys
  pipeline  pipeline container - parses and stores, has no internet access at all
  notify    notify container   - the only role that can reach the mail relay

Tasks are addressed by name, so no role ever imports another role's code.
"""
from celery import Celery
from celery.schedules import crontab

from app.config import get_settings

settings = get_settings()

_INCLUDE = {
    "crawler": ["app.worker.crawl_tasks"],
    "pipeline": ["app.worker.pipeline_tasks", "app.worker.intel_tasks"],
    "notify": ["app.worker.notify_tasks"],
    "enricher": ["app.worker.enrich_tasks", "app.worker.chain_tasks", "app.worker.feed_tasks"],
}

celery_app = Celery("kivuli", broker=settings.redis_url, include=_INCLUDE.get(settings.role, []))
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    task_compression="gzip",
    task_ignore_result=True,
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=200,
    broker_connection_retry_on_startup=True,
    broker_transport_options={"visibility_timeout": 3600},
    task_default_queue="pipeline",
    task_routes={
        "crawl.*": {"queue": "crawl"},
        "pipeline.*": {"queue": "pipeline"},
        "notify.*": {"queue": "notify"},
        "enrich.*": {"queue": "enrich"},
        "ai.*": {"queue": "enrich"},
        "chain.*": {"queue": "enrich"},
    },
    task_soft_time_limit=240,
    task_time_limit=300,
    beat_schedule={
        "schedule-due-crawls": {"task": "pipeline.schedule_due", "schedule": 60.0},
        "liveness-sweep": {"task": "pipeline.liveness_sweep", "schedule": 1800.0},
        "discover-sources": {"task": "pipeline.discover_sources", "schedule": crontab(hour="3", minute="20")},
        "tor-check": {"task": "crawl.tor_check", "schedule": 300.0},
        "dispatch-alert-email": {"task": "notify.dispatch_alerts", "schedule": 60.0},
        # Hourly: the task itself sends at the configured hour, which can be changed in the console.
        "daily-digest": {"task": "notify.send_digest", "schedule": crontab(minute="0")},
        "dispatch-integrations": {"task": "notify.dispatch_integrations", "schedule": 60.0},
        "evaluate-rules": {"task": "pipeline.evaluate_rules", "schedule": 300.0},
        "refresh-vulnerabilities": {"task": "pipeline.refresh_vulnerabilities", "schedule": 3600.0},
        "attack-surface-sweep": {"task": "pipeline.asm_sweep", "schedule": 3600.0},
        "provider-status": {"task": "enrich.status", "schedule": 600.0},
        "sync-provider-keys": {"task": "pipeline.sync_provider_keys", "schedule": 300.0},
    },
)


def enqueue(task: str, /, *, countdown: float | None = None, **kwargs) -> None:
    """Queue a task by name. The task name is positional-only so that a task may itself take an argument called ``name``."""
    celery_app.send_task(task, kwargs=kwargs, countdown=countdown)


# Console settings (app.runtime) apply in every worker before each task, within seconds of a change.
from celery.signals import task_prerun  # noqa: E402


@task_prerun.connect
def _apply_console_settings(**_kwargs):
    from app import runtime

    runtime.sync()

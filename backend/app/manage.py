"""Operator commands.

    python -m app.manage init                       migrate, create the index, seed
    python -m app.manage reindex                    rebuild the search index from PostgreSQL
    python -m app.manage upgrade-intel              backfill 1.1 intelligence onto existing findings
    python -m app.manage crawl-all                  queue a crawl of every approved source
    python -m app.manage create-user EMAIL ROLE     prompts for a password
    python -m app.manage test-email ADDRESS         send a test message through the notify worker
    python -m app.manage ops-alert --subject S      email an operations message (body on stdin) to ALERT_EMAIL_TO
"""
import argparse
import getpass
import logging
import sys
import time

from sqlalchemy import func, select, text

from app.config import get_settings
from app.db import get_engine, session_scope

log = logging.getLogger("kivuli.manage")
_LOCK_ID = 7_301_776  # advisory lock so concurrent containers do not migrate at once


def cmd_init(_args) -> None:
    from alembic import command
    from alembic.config import Config

    from app import seed
    from app.search import index as search_index

    engine = get_engine()
    for attempt in range(60):
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            break
        except Exception as exc:
            log.info("waiting for the database (%s)", type(exc).__name__)
            time.sleep(2)
    else:
        sys.exit("database did not become available")

    with engine.connect() as conn:
        conn.execute(text("SELECT pg_advisory_lock(:id)"), {"id": _LOCK_ID})
        try:
            command.upgrade(Config("alembic.ini"), "head")
        finally:
            conn.execute(text("SELECT pg_advisory_unlock(:id)"), {"id": _LOCK_ID})
            conn.commit()

    for attempt in range(90):
        try:
            if search_index.ensure_index():
                log.info("search index created")
            break
        except Exception as exc:
            log.info("waiting for the search node (%s)", type(exc).__name__)
            time.sleep(2)
    else:
        sys.exit("search node did not become available")

    with session_scope() as db:
        seed.run(db)
    try:
        # The enricher reads console-managed provider keys from Redis; make sure they are there after a restart.
        from app.intel import provider_store

        with session_scope() as db:
            provider_store.publish(db)
    except Exception as exc:
        log.info("provider keys not published (%s)", type(exc).__name__)
    try:
        # Rank the vulnerability catalogue soon after start rather than at the first hourly run.
        from app.worker.celery_app import enqueue

        enqueue("pipeline.refresh_vulnerabilities", countdown=120)
    except Exception as exc:  # the queue being briefly unavailable must not stop the API from starting
        log.info("vulnerability refresh not queued (%s)", type(exc).__name__)
    try:
        # Dark-web sources are found by discovery, which otherwise runs once a night. With none on file
        # (a fresh install), look soon after the first crawl has named some active groups.
        from sqlalchemy import select as _select

        from app.models import Source
        from app.worker.celery_app import enqueue

        with session_scope() as db:
            if db.scalar(_select(Source.id).where(Source.network == "onion").limit(1)) is None:
                enqueue("pipeline.discover_sources", countdown=600)
    except Exception as exc:
        log.info("discovery not queued (%s)", type(exc).__name__)
    log.info("initialisation complete")


def cmd_upgrade_intel(_args) -> None:
    """Bring findings collected before 1.1 up to date (techniques, exposure records, verification) and re-index them."""
    from app.worker.intel_tasks import backfill

    print("backfill:", backfill())


def cmd_reindex(_args) -> None:
    from app.worker.pipeline_tasks import reindex_all

    print(f"indexed {reindex_all()} findings")


def cmd_crawl_all(_args) -> None:
    from app.models import Source
    from app.worker.celery_app import enqueue

    with session_scope() as db:
        ids = list(db.scalars(select(Source.id).where(Source.status == "approved")))
    for source_id in ids:
        enqueue("pipeline.crawl_source", source_id=source_id)
    print(f"queued {len(ids)} sources")


def cmd_create_user(args) -> None:
    from app.models import ROLES, User
    from app.security import hash_password, password_problem, valid_email

    email = args.email.strip().lower()
    if not valid_email(email) or args.role not in ROLES:
        sys.exit(f"usage: create-user EMAIL {{{'|'.join(ROLES)}}}")
    password = getpass.getpass("Password: ") if sys.stdin.isatty() else sys.stdin.readline().rstrip("\n")
    if problem := password_problem(password):
        sys.exit(problem)
    with session_scope() as db:
        if db.scalar(select(func.count()).select_from(User).where(func.lower(User.email) == email)):
            sys.exit("a user with this email already exists")
        db.add(User(email=email, name=args.name or "", role=args.role, password_hash=hash_password(password)))
    print(f"created {args.role} {email}")


def cmd_test_email(args) -> None:
    from app.worker.celery_app import enqueue

    enqueue("notify.send_test", recipient=args.address)
    print("queued; see Settings > Email log in the console for the result")


def cmd_ops_alert(args) -> None:
    """Email an operations message (the server's health changed) straight away, without the queue:
    when something is broken the queue may be part of it. Run in the notify container, which can reach SMTP."""
    import html
    import sys

    from app.notify import mailer

    recipients = get_settings().default_recipients
    if not recipients:
        print("ALERT_EMAIL_TO is empty: nobody to tell", file=sys.stderr)
        raise SystemExit(1)
    body = sys.stdin.read()[:20000]
    mailer.send(recipients, args.subject, body, f"<pre style='font: 13px/1.4 monospace'>{html.escape(body)}</pre>")
    print(f"sent to {', '.join(recipients)}")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    parser = argparse.ArgumentParser(prog="manage", description=f"{get_settings().app_name} operator commands")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init").set_defaults(func=cmd_init)
    sub.add_parser("reindex").set_defaults(func=cmd_reindex)
    sub.add_parser("upgrade-intel").set_defaults(func=cmd_upgrade_intel)
    sub.add_parser("crawl-all").set_defaults(func=cmd_crawl_all)
    create = sub.add_parser("create-user")
    create.add_argument("email")
    create.add_argument("role")
    create.add_argument("--name", default="")
    create.set_defaults(func=cmd_create_user)
    test = sub.add_parser("test-email")
    test.add_argument("address")
    test.set_defaults(func=cmd_test_email)
    ops = sub.add_parser("ops-alert")
    ops.add_argument("--subject", required=True)
    ops.set_defaults(func=cmd_ops_alert)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

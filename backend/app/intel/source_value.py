"""How much a source is worth collecting: one score, 0-100, with the reasons.

For ranking the explorer, and above all the candidate queue: hundreds of
discovered sites wait for approval and an analyst needs to know which to look
at first. Built only from what Kivuli already knows about a source:

  relevance    how security-relevant its landing page reads (0-10)       up to 30
  references   how many other collected sites link to it                 up to 20
  yield        findings already collected from it                        up to 20
  kind         leak sites, forums and markets first, then trackers...    up to 10
  freshness    when it last had new or changed pages                     up to 10
  availability whether it answers                                        up to 10

Pure, so it is computed on read and tested without a database.
"""
from datetime import datetime, timedelta
from math import log2

KIND_POINTS = {"ransomware_leak_site": 10, "forum": 10, "marketplace": 10, "paste": 7, "tracker": 7, "vuln_feed": 5,
               "blog": 4, "news": 3, "other": 0}


def score(*, relevance: int, references: int, findings: int, category: str, last_changed: datetime | None,
          is_live: bool | None, failures: int, now: datetime) -> tuple[int, list[dict]]:
    """(score, factors). Each factor names a reason and its points, largest first."""
    factors: list[tuple[str, int]] = []

    def add(label: str, points: float) -> None:
        if points >= 1:
            factors.append((label, round(points)))

    add(f"Relevance of its title and context ({relevance}/10)", min(30, max(0, relevance) * 3))
    add(f"Linked from {references} other site{'s' if references != 1 else ''}", min(20, 7 * log2(1 + max(0, references))))
    add(f"{findings} finding{'s' if findings != 1 else ''} collected", min(20, 5 * log2(1 + max(0, findings))))
    add(category.replace("_", " ").capitalize(), KIND_POINTS.get(category, 0))
    if last_changed is not None:
        age = now - last_changed
        add("New pages this week" if age <= timedelta(days=7) else "New pages this month" if age <= timedelta(days=30)
            else "New pages in the last 90 days", 10 if age <= timedelta(days=7) else 6 if age <= timedelta(days=30) else 3 if age <= timedelta(days=90) else 0)
    if is_live and failures == 0:
        add("Answering", 10)
    elif is_live:
        add("Answering, with recent failures", 5)
    elif is_live is None:
        add("Not checked yet", 3)
    factors.sort(key=lambda f: -f[1])
    return min(100, sum(p for _, p in factors)), [{"label": label, "points": p} for label, p in factors]

# Documentation

| Document | For | Covers |
|---|---|---|
| [OPERATIONS.md](OPERATIONS.md) | Whoever runs the server | Installing (install.sh, by hand, beside other websites), configuration, keys, every ctl.sh command, backups, updates, the server shell, monitoring, troubleshooting, security checklist, moving, uninstalling |
| [ROADMAP.md](ROADMAP.md) | Everyone | Next steps and what each needs, and what will not be built |
| [USER-GUIDE.md](USER-GUIDE.md) | Researchers and analysts | Every screen, the full search language, research crawls, investigations, alerts, common tasks, glossary |
| [TECHNICAL.md](TECHNICAL.md) | Engineers and operators | Architecture, containers and networks, collection, the processing pipeline, extraction, scoring formulas, search internals, alerting, enrichment and AI, access control, operations, extending |
| [COVERAGE.md](COVERAGE.md) | Anyone deciding what to rely on | What is collected and stored, every capability with its status, what it will never do, what is not built, how far each part has been proven, where accuracy is limited |
| [REFERENCE.md](REFERENCE.md) | Integrators | Generated from the running code: all 150 API operations with required role, every table and column, every setting, scheduled tasks, fixed value lists |
| [GAP-ANALYSIS.md](GAP-ANALYSIS.md) | History | The audit against modern CTI capabilities, and what each phase delivered and validated |
| [../README.md](../README.md) | First-time setup | Starting it, the research workflow in brief, the security model |

## Where to start

- **Using it:** USER-GUIDE.md, sections 3 to 7.
- **Installing and running it:** OPERATIONS.md.
- **What comes next:** ROADMAP.md.
- **Trusting it:** COVERAGE.md, sections 5 to 8.
- **Integrating with it:** REFERENCE.md, then TECHNICAL.md sections 13 and 14.
- **Changing it:** TECHNICAL.md sections 19 and 20.

## Keeping it current

REFERENCE.md is generated. After any change to the API, the models, the
settings or the schedules:

```bash
./ctl.sh docker compose exec -T api python - < tools/gen_reference.py > docs/REFERENCE.md
```

The other documents are written by hand. When behaviour changes, update the
section that describes it, and move the line in COVERAGE.md section 7 when
something is proven that was not.

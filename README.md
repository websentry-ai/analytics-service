# Analytics Service

Internal API for customer analytics metrics.

## Setup

```bash
pip install -r requirements.txt
python app.py
```

## Endpoints

- `GET /health` — health check
- `GET /api/v1/metrics` — aggregated metrics
- `GET /api/v1/metrics/realtime` — realtime metrics stream

## Configuration

All config in `config/settings.json`. See `docs/MIGRATION_v2_to_v3.md` for migration guide from env vars.

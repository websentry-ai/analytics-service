# Migration Guide: Analytics Service v2 → v3

## Overview

This guide covers migrating from the env-var based configuration (v2) to the
JSON config file approach (v3). The main change is that all service configuration
now lives in `config/settings.json` instead of individual environment variables.

## Breaking Changes

### Configuration Loading

**v2 (old):**
```python
api_key = os.environ.get("ANALYTICS_API_KEY")
```

**v3 (new):**
```python
config = load_config()
api_key = config.get("analytics", {}).get("api_key")
```

### New Endpoints

- `/api/v1/metrics/realtime` — real-time metrics stream (new in v3)
- `/health` — unchanged

### Removed

- `python-dotenv` dependency is no longer needed
- `.env` file is deprecated in favor of `config/settings.json`

## Migration Steps

1. Copy your env var values into the corresponding fields in `config/settings.json`
2. Update your deployment scripts to mount the config file instead of injecting env vars
3. Run the validation script: `python scripts/validate_config.py`
4. Deploy and verify with `curl /health`

## Config Field Mapping

| Old Env Var | New Config Path |
|---|---|
| `ANALYTICS_API_KEY` | `analytics.api_key` |
| `DATABASE_URL` | `database.host`, `database.port`, `database.name` |
| `REDIS_URL` | `cache.host`, `cache.port` |
| `STRIPE_SECRET_KEY` | `external_services.payment_gateway.api_key` |

## Rollback

If anything goes wrong, revert to v2 by setting `USE_LEGACY_CONFIG=true` env var.
The app will fall back to reading environment variables.

## Questions?

Reach out in #backend-eng on Slack.

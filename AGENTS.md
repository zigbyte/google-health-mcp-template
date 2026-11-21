# AGENTS.md — Setup, Maintenance & Troubleshooting Guide

Instructions for AI coding agents helping a user deploy, customize, or troubleshoot this **Google Health MCP Bridge** on Google Cloud Run.

---

## Architectural Invariants
1. **Never commit secrets.** Store `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and `JWT_SIGNING_KEY` in a password manager or Google Secret Manager—never in `.env` or Git.
2. **Keep Cloud Run free-tier settings:** Deploy in an Always Free region (`us-central1`) with `--min-instances 0` and `--max-instances 1`. Setting `--min-instances 1` incurs monthly charges.
3. **Keep `stateless_http=True`:** Stateful Streamable HTTP (`stateless_http=False`) opens a persistent `GET /mcp` SSE stream that Cloud Run times out/truncates (`Truncated response body`), hanging MCP clients mid-turn.
4. **Keep `FilterOAuthScopesMiddleware` as raw ASGI middleware:** Some MCP clients (including Gemini) inject client-internal scopes (such as `ACCESS_VIEW_MANAGE_MCP_CONTENT`, `SHARE_THROUGH_MCP_CONVERSATION_INFO`, `TRIGGER_TOOLS_AND_FUNCTION`) into `/authorize`. Stripping non-Google scopes before FastMCP validates them prevents `invalid_scope` errors. Avoid Starlette's `BaseHTTPMiddleware` with MCP HTTP apps.
5. **Keep `ALLOWED_EMAIL` fail-closed:** When running an OAuth app in **Production** mode (unverified, personal use), `_get_verified_token()` must reject requests whenever `ALLOWED_EMAIL` is set and the token's `email` claim is missing or does not match.
6. **Persist OAuth state in Firestore (`USE_FIRESTORE=true`) + set `JWT_SIGNING_KEY`:** Without both, Cloud Run cold starts wipe dynamic client registrations and JWT keys, causing `401 invalid_token` (`JTI mapping not found`). `_build_auth_provider()` fails closed on startup if `USE_FIRESTORE=true` without `JWT_SIGNING_KEY`.
7. **Keep `GracefulGoogleProvider` OAuth resilience & `.pyc` precompilation:** Preserve the 5-minute Fernet-encrypted idempotent refresh-token grace window (`load_refresh_token` / `exchange_refresh_token` / `revoke_token`), 30-day FastMCP access tokens (`fastmcp_access_token_expiry_seconds=2592000`), 5-minute proactive upstream refresh (`token_expiry_threshold_seconds=300`, `cache_ttl_seconds=300`), `.pyc` precompilation in `Dockerfile`, and pinned `fastmcp-slim[server]==4.2.2` + `py-key-value-aio[firestore,wrappers-encryption]==0.5.0` in `requirements.txt`.

---

## Useful Commands

### Inspect Cloud Run Logs
```bash
gcloud run services logs read google-health-mcp --region us-central1 --limit 50
```

### Verify OAuth Discovery Endpoints
```bash
curl -sS "${SERVICE_URL}/.well-known/oauth-authorization-server"
curl -sS "${SERVICE_URL}/.well-known/oauth-protected-resource/mcp"
```

### Redeploy After Code Changes
```bash
gcloud run deploy google-health-mcp --source . --region us-central1 --quiet
```
> **macOS TCC Tip:** If `gcloud` fails during source upload with `PermissionError: [Errno 1] Operation not permitted` when the repo is inside `~/Documents`, copy `server.py`, `requirements.txt`, `Dockerfile`, and `.dockerignore` into a temporary directory outside `~/Documents` (e.g., `/tmp/health-mcp-deploy`), deploy from there, and delete the temporary directory afterward.

---

## Troubleshooting Playbook

### 1. `invalid_scope: Client was not registered with scope ...`
* **Cause:** The MCP client sent extra internal scopes on `/authorize`.
* **Fix:** Ensure `FilterOAuthScopesMiddleware` is attached in `mcp.http_app(..., middleware=[Middleware(FilterOAuthScopesMiddleware)])`.

### 2. Client hangs on *"Connecting..."* or logs show `Truncated response body`
* **Cause:** Stateful SSE streams timing out on Cloud Run.
* **Fix:** Verify `stateless_http=True` is set in `mcp.http_app(...)`.

### 3. `401 Unauthorized` / `JTI mapping not found`
* **Cause:** Missing `USE_FIRESTORE=true` or `JWT_SIGNING_KEY`, missing `roles/datastore.user` on the Cloud Run service account, or a stale token minted before Firestore was enabled.
* **Fix:** Verify env vars + IAM role, then disconnect and reconnect the MCP connector once in the client UI.

### 4. `400 INVALID_DATA_POINT_FILTER` from Google Health API v4
* **Cause:** Google Health API v4 requires:
  * **Hyphens** in the URL path `dataType` (e.g., `daily-heart-rate-variability`), but **underscores** in the `filter` prefix (e.g., `daily_heart_rate_variability.date`).
  * Strictly **`<`** (exclusive upper bound) for date/time ranges, not `<=`.
* **Fix:** Use `_next_day_iso(end)` with `< "{end_exclusive}"`.

### 5. Sessions expire after 7 days
* **Cause:** Google Cloud OAuth Consent Screen is still in **Testing** mode.
* **Fix:** Complete required **Branding** fields, switch **Audience → Publishing status** to **In production** (no public verification required for personal use under 100 users), and reconnect once in the MCP client.

### 6. Extending With More Google Health Metrics
* Add read-only tools for additional v4 `dataTypes` (e.g., `daily-resting-heart-rate`, `daily-oxygen-saturation`, `active-minutes`, `weight`, or `total-calories` via `:rollUp`).
* Aggregate high-frequency samples into daily summaries and keep `max_pages` bounded so tool responses stay fast and compact.

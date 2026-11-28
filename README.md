# Google Health MCP Bridge (Cloud Run Template)

A self-hosted, read-only **Model Context Protocol (MCP)** bridge that connects your **Google Health API v4** data (Fitbit, Pixel Watch, and cloud-synced Google Health metrics) to **Gemini** (web and mobile) over **Streamable HTTP**—running on **Google Cloud Run + Firestore** within Google Cloud's **Always Free tier** (\$0/month for personal use).

---

## Architecture

```text
Gemini (Web & Mobile)
   │  Stateless Streamable HTTP + OAuth 2.0 Bearer Token
   ▼
Google Cloud Run (your-service.run.app)
   ├── FilterOAuthScopesMiddleware  → strips client-internal scopes on /authorize
   ├── GracefulGoogleProvider       → FastMCP OAuth 2.0 proxy + 30d access token, 5m proactive upstream refresh, & 5m idempotent refresh grace window
   ├── FirestoreStore (default)     → persists OAuth client registrations, tokens, & encrypted grace records across cold starts
   └── Health Tools                 → queries/logs https://health.googleapis.com/v4/users/me/dataTypes/*
```

### Cold-Start & OAuth Resilience (Always Free Tier)
* **30-day FastMCP access tokens + proactive upstream refresh:** `GracefulGoogleProvider` issues 30-day FastMCP access tokens (`fastmcp_access_token_expiry_seconds=2592000`) and transparently refreshes Google's 1-hour upstream token 5 minutes before expiry (`token_expiry_threshold_seconds=300`, `cache_ttl_seconds=300`), eliminating routine `/token` calls during cold starts.
* **5-minute idempotent refresh grace window:** Rotated refresh tokens remain valid for 5 minutes (stored Fernet-encrypted in Firestore) so if a client times out during a cold start and retries `/token` with the previous refresh token, it receives the already-minted token set instead of `401 invalid_grant`.
* **Faster cold starts:** `Dockerfile` pre-compiles `.pyc` bytecode during build and `requirements.txt` pins `fastmcp-slim[server]==4.2.2` and `py-key-value-aio[firestore,wrappers-encryption]==0.5.0`.

### Exposed MCP Tools
| Tool | Google Health v4 Data Type | Access / Default Window |
| :--- | :--- | :--- |
| `get_steps` | `steps` (`dataPoints:rollUp`) | Read · Last 7 days (reconciled, local-timezone daily totals) |
| `get_sleep` | `sleep` | Read · Last 7 days (sessions) |
| `get_heart_rate` | `heart-rate` | Read · Last 3 days (daily min/max/avg BPM) |
| `get_daily_hrv` | `daily-heart-rate-variability` | Read · Last 14 days |
| `get_exercises` | `exercise` | Read · Last 14 days |
| `get_meals` | `nutrition-log` | Read · Last 2 days |
| `get_hydration` | `hydration-log` | Read · Last 2 days (daily mL & fl oz) |
| `get_recovery_vitals` | `daily-resting-heart-rate`, `daily-respiratory-rate`, `daily-oxygen-saturation`, `daily-heart-rate-variability` | Read · Last 14 days (merged daily) |
| `get_daily_energy` | `total-calories:rollUp`, `active-zone-minutes`, `active-minutes` | Read · Last 7 days (TDEE & AZM) |
| `get_body_composition` | `weight`, `body-fat` | Read · Last 30 days (lbs/kg, EWMA trend, body fat %, auto-attached profile & goals) |
| `get_user_profile` | Env physiology + Firestore `user_profile/goals` | Read · Base profile, North Star + Phase Milestones, computed athletic bands & pace |
| `update_user_goals` | Firestore `user_profile/goals` (+ `history/`) | Write · Update North Star, `optimal` vs `custom` weight, pace, nutrition phase, Phase milestones |
| `get_daily_cut_summary` | Combined TDEE + meals + hydration + weight + recovery + glucose + supplements | Read · Last 7 days (1-call net deficit with completeness gate, EWMA weight, RHR delta, sleep debt, cycle context & CGM summary) |
| `get_glucose` | LibreLinkUp → Firestore `glucose_days` | Read · Last 7 days (live reading + trend, TIR 70–140 & 70–180, Mean, %CV, GMI, fasting, 2h post-meal spikes) |
| `log_meal` | `nutrition-log` | Write · Log food, calories, macros, meal type |
| `log_water` | `hydration-log` | Write · Log water intake (mL) |
| `log_supplement_or_med` | Firestore `supplement_med_logs` | Write · Log vitamins, supplements, or medications (dose, unit, timing) |
| `get_supplement_med_logs` | Firestore `supplement_med_logs` | Read · Last 14 days supplement/medication logs & adherence counts |
| `delete_supplement_med_log` | Firestore `supplement_med_logs` | Delete · Remove a supplement/medication log by `log_id` |
| `log_strength_sets` | Firestore `strength_logs` | Write · Log straight or pyramid sets (reps, weight, RPE) |
| `get_strength_logs` | Firestore `strength_logs` | Read · Last 14 days (filter by exercise, volume, top weight & Epley e1RM) |
| `delete_strength_log` | Firestore `strength_logs` | Delete · Remove a mistyped strength log by `log_id` |
| `log_mindfulness_session` | Firestore `mindfulness_logs` | Write · Log meditation/mindfulness (duration, Calm %, Stillness %, HR) |
| `get_mindfulness_logs` | Firestore `mindfulness_logs` | Read · Last 14 days (total minutes, avg Calm/Stillness %) |
| `delete_mindfulness_log` | Firestore `mindfulness_logs` | Delete · Remove a mindfulness log by `log_id` |
| `delete_meals` | `nutrition-log` (`:batchDelete`) | Delete · Remove duplicate/mistyped meals by resource `name` |
| `delete_hydration_logs` | `hydration-log` (`:batchDelete`) | Delete · Remove duplicate/mistyped water logs by resource `name` |
| `log_daily_checkin` | Firestore `daily_checkins` | Write · Daily soreness (0-10), `pain_types` (`doms`/`joint_tendon`), cramp warning, `cycle_day_1`, energy, waist (in/cm), notes |
| `get_daily_checkins` | Firestore `daily_checkins` | Read · Last 30 days readiness check-ins, latest waist & derived `cycle_context` |
| `query_health_data_type` | Any v4 `dataType` | Read · Custom filter |

---

## Prerequisites
* A Google account with health data synced to Google Health (e.g., Fitbit / Pixel Watch). *(Note: Android Health Connect is on-device only and does not expose a cloud API.)*
* A Google Cloud project with an active billing account (required for Cloud Run; stays \$0/month under Always Free limits).
* [`gcloud` CLI](https://cloud.google.com/sdk/docs/install) installed and authenticated (`gcloud auth login`).

---

## Step-by-Step Deployment

### 1. Select Your GCP Project & Enable APIs
```bash
export PROJECT_ID="YOUR_PROJECT_ID"
gcloud config set project "$PROJECT_ID"

gcloud services enable \
  run.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  firestore.googleapis.com
```
Also enable **Google Health API** in the Google Cloud Console under **APIs & Services → Library**.

### 2. Create a Free-Tier Firestore Database (Persists Sessions Across Cold Starts)
```bash
gcloud firestore databases create \
  --location=us-central1 \
  --type=firestore-native

PROJECT_NUMBER=$(gcloud projects describe "$PROJECT_ID" --format="value(projectNumber)")
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
  --role="roles/datastore.user"
```

### 3. Configure Google OAuth
1. Open **Google Cloud Console → Google Auth Platform → Branding** (or **APIs & Services → OAuth consent screen**) and fill in:
   * App name, User support email, Application home page, Privacy policy link, and Developer contact email.
2. Under **Data Access / Scopes**, add:
   * `openid`
   * `https://www.googleapis.com/auth/userinfo.email`
   * `https://www.googleapis.com/auth/googlehealth.activity_and_fitness.readonly`
   * `https://www.googleapis.com/auth/googlehealth.health_metrics_and_measurements.readonly`
   * `https://www.googleapis.com/auth/googlehealth.sleep.readonly`
   * `https://www.googleapis.com/auth/googlehealth.nutrition.readonly`
   * `https://www.googleapis.com/auth/googlehealth.nutrition.writeonly`
3. Under **Audience**, switch **Publishing status** from *Testing* to **In production** (personal apps under 100 users do not need public verification, and *In production* prevents Google's 7-day refresh token expiration).
4. Under **Clients → Create Client → Web application**, create an OAuth 2.0 Web Client and save your **Client ID** and **Client Secret** in a password manager.

### 4. Deploy to Cloud Run
Generate a stable signing key so tokens stay valid across container restarts:
```bash
JWT_SIGNING_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
```

Deploy to `us-central1` with scale-to-zero (`--min-instances 0`, `--max-instances 1`) to stay inside the Always Free tier:
```bash
gcloud run deploy google-health-mcp \
  --source . \
  --region us-central1 \
  --allow-unauthenticated \
  --min-instances 0 \
  --max-instances 1 \
  --memory 512Mi \
  --set-env-vars "GOOGLE_CLIENT_ID=YOUR_CLIENT_ID,GOOGLE_CLIENT_SECRET=YOUR_CLIENT_SECRET,JWT_SIGNING_KEY=${JWT_SIGNING_KEY},BASE_URL=https://placeholder.run.app,ALLOWED_EMAIL=you@example.com,USE_FIRESTORE=true"
```

Copy the **Service URL** printed by `gcloud` (e.g., `https://google-health-mcp-xxxxx-uc.a.run.app`), then update `BASE_URL`:
```bash
export SERVICE_URL="https://google-health-mcp-xxxxx-uc.a.run.app"

gcloud run services update google-health-mcp \
  --region us-central1 \
  --update-env-vars "BASE_URL=${SERVICE_URL}"
```

### 5. Add the Authorized Redirect URI
Back in **Google Cloud Console → Google Auth Platform → Clients → your OAuth Web Client**, add this **Authorized redirect URI**:
```text
https://google-health-mcp-xxxxx-uc.a.run.app/auth/callback
```
Click **Save**.

### 6. Connect to Gemini
1. Open [gemini.google.com](https://gemini.google.com) → **Settings → Connected Apps → Add Custom MCP Connector** (ensure *Keep Activity* is enabled).
2. Set:
   * **Name:** `Google Health`
   * **MCP Server URL:** `https://google-health-mcp-xxxxx-uc.a.run.app/mcp`
3. Complete the Google sign-in prompt (click **Advanced → Go to …** once if your app is unverified).
4. *(Optional)* In Gemini **Settings → Saved info**, add a rule telling Gemini to always use your `Google Health` connected app whenever you ask about steps, sleep, heart rate, HRV, or workouts.

### 7. Optional ($0/month): Cloud Scheduler Keep-Warm Ping
Cloud Run scales to zero after ~15 minutes of inactivity. You can optionally create 1 free Cloud Scheduler job (3 jobs/month Always Free per billing account; under request-based billing, idle time between pings is not billed) to keep the container warm most of the time:
```bash
gcloud services enable cloudscheduler.googleapis.com

gcloud scheduler jobs create http google-health-mcp-keepwarm \
  --location=us-central1 \
  --schedule="*/10 * * * *" \
  --uri="${SERVICE_URL}/.well-known/oauth-authorization-server" \
  --http-method=GET \
  --attempt-deadline=30s
```

### 8. Optional: Base Physiology Profile & Dynamic Goals
Set optional environment variables on Cloud Run so Gemini automatically receives your timezone, BMI, Mifflin-St Jeor BMR, Waist-to-Height Ratio (WHtR), athletic recomp anchors, and safe pace guardrails:
```bash
gcloud run services update google-health-mcp \
  --region us-central1 \
  --update-env-vars "USER_TIMEZONE=America/Toronto,USER_SEX=female,USER_HEIGHT_CM=166,USER_BIRTH_YEAR=1990"
```
Mutable goals (`target_weight_mode`: `optimal` | `custom`, `pace_mode`: `optimal` | `slow` | `normal` | `medium_fast` | `fast` | `by_date`, `nutrition_phase`: `cut` | `refeed` | `diet_break`, and Phase milestones) are persisted in Firestore (`user_profile/goals`) and editable via Gemini (`update_user_goals`) or the companion local dashboard.

### 9. Optional ($0/month): FreeStyle Libre 3 / 3 Plus CGM via LibreLinkUp
FreeStyle Libre 3 apps do not sync natively to Google Health, so the bridge pulls live readings from Abbott's **LibreLinkUp** follower API and archives 5-minute points into daily Firestore buckets (`glucose_days/YYYY-MM-DD`, ~15 KB/day):
1. In your official **FreeStyle Libre 3** app → **Menu → Connected Apps → LibreLinkUp → Manage → Add Connection**, invite a follower email (a Gmail `+llu` alias works great).
2. Install the **LibreLinkUp** app (**must match the same country/region** as your Libre 3 account), create the follower account with that invited email, and tap **Accept** on the connection invite.
3. Add the follower credentials and a random `CRON_SECRET` to Cloud Run:
   ```bash
   CRON_SECRET=$(openssl rand -hex 24)
   gcloud run services update google-health-mcp \
     --region us-central1 \
     --update-env-vars "LLU_EMAIL=you+llu@example.com,LLU_PASSWORD=YOUR_LLU_PASSWORD,LLU_VERSION=4.16.0,CRON_SECRET=${CRON_SECRET}"
   ```
4. Create a free 15-minute Cloud Scheduler job (uses 2 of 3 free jobs/month) so history is archived 24/7 past LibreLinkUp's 12-hour window:
   ```bash
   gcloud scheduler jobs create http google-health-mcp-glucose-sync \
     --location=us-central1 \
     --schedule="*/15 * * * *" \
     --uri="${SERVICE_URL}/cron/sync-glucose" \
     --http-method=POST \
     --headers="X-Cron-Secret=${CRON_SECRET}"
   ```
*(The bridge caches the LibreLinkUp JWT token + SHA-256 `Account-Id` header in Firestore `user_profile/llu_session` to avoid Abbott login rate limits.)*

### 10. Recommended ($0/month): Auto-Prune Old Artifact Registry Images & Budget Alert
Keep Artifact Registry container storage under the 500 MB Always Free limit by retaining only the 2 most recent deploys:
```bash
cat << 'EOF' > /tmp/ar-cleanup-policy.json
[
  {"name": "keep-latest-2", "action": {"type": "Keep"}, "mostRecentVersions": {"keepCount": 2}},
  {"name": "delete-old", "action": {"type": "Delete"}, "condition": {"tagState": "ANY", "olderThan": "86400s"}}
]
EOF
gcloud artifacts repositories set-cleanup-policies cloud-run-source-deploy \
  --location=us-central1 --policy=/tmp/ar-cleanup-policy.json --no-dry-run
```

Set a monthly budget alert as a safety net:
```bash
BILLING_ACCOUNT=$(gcloud billing projects describe "$PROJECT_ID" --format="value(billingAccountName)" | cut -d/ -f2)
gcloud services enable billingbudgets.googleapis.com

gcloud billing budgets create \
  --billing-account="$BILLING_ACCOUNT" \
  --display-name="Health MCP Monthly Alert" \
  --budget-amount=5USD \
  --filter-projects="projects/${PROJECT_NUMBER}" \
  --threshold-rule=percent=0.5 \
  --threshold-rule=percent=0.8 \
  --threshold-rule=percent=1.0 \
  --threshold-rule=percent=1.0,basis=forecasted-spend
```
*(Replace `5USD` with your billing account's currency code if different.)*

---

## Troubleshooting & Agent Instructions
See [AGENTS.md](AGENTS.md) for deployment tips, Google Health API v4 filter gotchas, and troubleshooting steps.

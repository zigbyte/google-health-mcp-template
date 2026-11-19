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
   ├── FastMCP GoogleProvider       → handles MCP OAuth 2.0 proxy + Google sign-in
   ├── FirestoreStore (default)     → persists OAuth client registrations & tokens across cold starts
   └── Read-Only Health Tools       → queries https://health.googleapis.com/v4/users/me/dataTypes/*
```

### Exposed MCP Tools
| Tool | Google Health v4 Data Type | Default Window |
| :--- | :--- | :--- |
| `get_steps` | `steps` | Last 7 days (daily totals) |
| `get_sleep` | `sleep` | Last 7 days (sessions) |
| `get_heart_rate` | `heart-rate` | Last 3 days (daily min/max/avg BPM) |
| `get_daily_hrv` | `daily-heart-rate-variability` | Last 14 days |
| `get_exercises` | `exercise` | Last 14 days |
| `query_health_data_type` | Any v4 `dataType` | Custom filter |

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

### 7. Recommended: Set a Monthly Budget Alert
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

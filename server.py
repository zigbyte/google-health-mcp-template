"""
Google Health MCP Bridge for Gemini (hosted on Google Cloud Run).

Exposes read-only tools backed by the Google Health API v4
(https://health.googleapis.com/v4) over Streamable HTTP using FastMCP
and Google OAuth 2.0.
"""

from __future__ import annotations

import os
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import parse_qsl, urlencode

import httpx
import uvicorn
from fastmcp import FastMCP
from fastmcp.server.auth.providers.google import GoogleProvider
from fastmcp.server.dependencies import get_access_token
from starlette.middleware import Middleware
from starlette.types import ASGIApp, Receive, Scope, Send

HEALTH_API_BASE = "https://health.googleapis.com/v4"

HEALTH_SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/googlehealth.activity_and_fitness.readonly",
    "https://www.googleapis.com/auth/googlehealth.health_metrics_and_measurements.readonly",
    "https://www.googleapis.com/auth/googlehealth.sleep.readonly",
    "https://www.googleapis.com/auth/googlehealth.nutrition.readonly",
    "https://www.googleapis.com/auth/googlehealth.nutrition.writeonly",
]


def _build_client_storage():
    """Return a Firestore-backed AsyncKeyValue store when USE_FIRESTORE=true."""
    if os.environ.get("USE_FIRESTORE", "").strip().lower() not in ("1", "true", "yes"):
        return None

    from key_value.aio.stores.firestore import FirestoreStore

    database = os.environ.get("FIRESTORE_DATABASE", "(default)")
    return FirestoreStore(database=database)


def _build_auth_provider() -> GoogleProvider:
    client_id = os.environ.get("GOOGLE_CLIENT_ID", "")
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET", "")
    base_url = os.environ.get("BASE_URL", "http://localhost:8080").rstrip("/")
    jwt_signing_key = os.environ.get("JWT_SIGNING_KEY") or None

    if not client_id or not client_secret:
        raise RuntimeError(
            "GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables must be set."
        )

    return GoogleProvider(
        client_id=client_id,
        client_secret=client_secret,
        base_url=base_url,
        redirect_path="/auth/callback",
        required_scopes=HEALTH_SCOPES,
        jwt_signing_key=jwt_signing_key,
        client_storage=_build_client_storage(),
    )


mcp = FastMCP(
    name="Google Health Bridge",
    instructions=(
        "Bridge to the user's Google Health API v4 data: read steps, sleep, "
        "heart rate, daily HRV, exercises, and meals; log meals and water intake. "
        "Dates use YYYY-MM-DD format."
    ),
    auth=_build_auth_provider(),
)


def _get_verified_token() -> str:
    """Return the upstream Google OAuth access token, enforcing ALLOWED_EMAIL if set."""
    access_token = get_access_token()
    if access_token is None or not access_token.token:
        raise PermissionError("No authenticated Google OAuth token available.")

    allowed_email = os.environ.get("ALLOWED_EMAIL", "").strip().lower()
    if allowed_email:
        claims = access_token.claims or {}
        user_email = str(claims.get("email", "")).strip().lower()
        if not user_email or user_email != allowed_email:
            raise PermissionError(
                f"Access denied for '{user_email or 'unknown'}'. This personal bridge is restricted."
            )

    return access_token.token


def _parse_date(date_str: str) -> datetime:
    try:
        return datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError as exc:
        raise ValueError(f"Invalid date '{date_str}'. Expected YYYY-MM-DD.") from exc


def _default_date_range(
    start_date: str | None, end_date: str | None, default_days: int = 7
) -> tuple[str, str]:
    today = datetime.now(timezone.utc).date()
    if not end_date:
        end_dt = today
    else:
        end_dt = _parse_date(end_date).date()

    if not start_date:
        start_dt = end_dt - timedelta(days=default_days - 1)
    else:
        start_dt = _parse_date(start_date).date()

    if start_dt > end_dt:
        raise ValueError("start_date must be on or before end_date.")

    return start_dt.isoformat(), end_dt.isoformat()


def _next_day_iso(date_str: str) -> str:
    return (_parse_date(date_str).date() + timedelta(days=1)).isoformat()


async def _fetch_data_points(
    data_type: str,
    filter_expr: str | None = None,
    page_size: int = 1000,
    max_pages: int = 2,
) -> list[dict[str, Any]]:
    """Query Google Health API v4 dataPoints with bounded pagination."""
    token = _get_verified_token()
    url = f"{HEALTH_API_BASE}/users/me/dataTypes/{data_type}/dataPoints"
    headers = {"Authorization": f"Bearer {token}"}

    points: list[dict[str, Any]] = []
    page_token: str | None = None

    async with httpx.AsyncClient(timeout=15.0) as client:
        for _ in range(max_pages):
            params: dict[str, Any] = {"pageSize": min(max(page_size, 1), 10000)}
            if filter_expr:
                params["filter"] = filter_expr
            if page_token:
                params["pageToken"] = page_token

            resp = await client.get(url, headers=headers, params=params)
            if resp.status_code == 401:
                raise PermissionError(
                    "Google Health API rejected the token (401). Please re-authenticate."
                )
            if resp.status_code == 403:
                raise PermissionError(
                    f"Google Health API returned 403 Forbidden for '{data_type}'. "
                    "Verify the Google Health API is enabled and the required scope was granted."
                )
            resp.raise_for_status()

            payload = resp.json()
            batch = payload.get("dataPoints", [])
            points.extend(batch)

            page_token = payload.get("nextPageToken")
            if not page_token:
                break

    return points


@mcp.tool
async def get_steps(
    start_date: str | None = None,
    end_date: str | None = None,
) -> dict[str, Any]:
    """
    Get daily step totals from Google Health for a date range (YYYY-MM-DD).
    Defaults to the last 7 days if dates are omitted.
    """
    start, end = _default_date_range(start_date, end_date, default_days=7)
    end_exclusive = _next_day_iso(end)
    filter_expr = (
        f'steps.interval.start_time >= "{start}T00:00:00Z" '
        f'AND steps.interval.start_time < "{end_exclusive}T00:00:00Z"'
    )

    points = await _fetch_data_points("steps", filter_expr=filter_expr, page_size=5000)

    daily_totals: dict[str, int] = defaultdict(int)
    for pt in points:
        steps_obj = pt.get("steps", {})
        interval = steps_obj.get("interval", {})
        ts = interval.get("startTime") or interval.get("civilStartTime") or ""
        day = ts[:10] if len(ts) >= 10 else "unknown"
        count = steps_obj.get("count") or steps_obj.get("countSum") or 0
        daily_totals[day] += int(count)

    ordered = dict(sorted(daily_totals.items()))
    return {
        "start_date": start,
        "end_date": end,
        "total_steps": sum(ordered.values()),
        "daily_steps": ordered,
        "raw_intervals_fetched": len(points),
    }


@mcp.tool
async def get_sleep(
    start_date: str | None = None,
    end_date: str | None = None,
) -> dict[str, Any]:
    """
    Get sleep sessions (duration, stages, wake times) for a date range (YYYY-MM-DD).
    Defaults to the last 7 days if dates are omitted.
    """
    start, end = _default_date_range(start_date, end_date, default_days=7)
    end_exclusive = _next_day_iso(end)
    filter_expr = (
        f'sleep.interval.civil_end_time >= "{start}T00:00:00" '
        f'AND sleep.interval.civil_end_time < "{end_exclusive}T00:00:00"'
    )

    points = await _fetch_data_points("sleep", filter_expr=filter_expr, page_size=200)
    return {
        "start_date": start,
        "end_date": end,
        "session_count": len(points),
        "sessions": points,
    }


@mcp.tool
async def get_heart_rate(
    start_date: str | None = None,
    end_date: str | None = None,
    include_samples: bool = False,
) -> dict[str, Any]:
    """
    Get heart rate summary (min, max, average BPM per day) for a date range (YYYY-MM-DD).
    Defaults to the last 3 days. Set include_samples=True to include up to 200 raw samples.
    """
    start, end = _default_date_range(start_date, end_date, default_days=3)
    end_exclusive = _next_day_iso(end)
    filter_expr = (
        f'heart_rate.sample_time.physical_time >= "{start}T00:00:00Z" '
        f'AND heart_rate.sample_time.physical_time < "{end_exclusive}T00:00:00Z"'
    )

    points = await _fetch_data_points(
        "heart-rate", filter_expr=filter_expr, page_size=5000
    )

    by_day: dict[str, list[float]] = defaultdict(list)
    for pt in points:
        hr = pt.get("heartRate", {})
        sample_time = hr.get("sampleTime", {})
        ts = sample_time.get("physicalTime") or sample_time.get("civilTime") or ""
        day = ts[:10] if len(ts) >= 10 else "unknown"
        bpm = hr.get("beatsPerMinute")
        if bpm is not None:
            by_day[day].append(float(bpm))

    daily_summary = {}
    for day, values in sorted(by_day.items()):
        daily_summary[day] = {
            "min_bpm": round(min(values), 1),
            "max_bpm": round(max(values), 1),
            "avg_bpm": round(sum(values) / len(values), 1),
            "sample_count": len(values),
        }

    result: dict[str, Any] = {
        "start_date": start,
        "end_date": end,
        "daily_summary": daily_summary,
        "total_samples_fetched": len(points),
    }
    if include_samples:
        result["samples"] = points[:200]
    return result


@mcp.tool
async def get_daily_hrv(
    start_date: str | None = None,
    end_date: str | None = None,
) -> dict[str, Any]:
    """
    Get daily Heart Rate Variability (HRV) records for a date range (YYYY-MM-DD).
    Defaults to the last 14 days.
    """
    start, end = _default_date_range(start_date, end_date, default_days=14)
    end_exclusive = _next_day_iso(end)
    filter_expr = (
        f'daily_heart_rate_variability.date >= "{start}" '
        f'AND daily_heart_rate_variability.date < "{end_exclusive}"'
    )

    points = await _fetch_data_points(
        "daily-heart-rate-variability", filter_expr=filter_expr, page_size=200
    )
    return {
        "start_date": start,
        "end_date": end,
        "record_count": len(points),
        "records": points,
    }


@mcp.tool
async def get_exercises(
    start_date: str | None = None,
    end_date: str | None = None,
) -> dict[str, Any]:
    """
    Get recorded workouts / exercise sessions for a date range (YYYY-MM-DD).
    Defaults to the last 14 days.
    """
    start, end = _default_date_range(start_date, end_date, default_days=14)
    end_exclusive = _next_day_iso(end)
    filter_expr = (
        f'exercise.interval.civil_start_time >= "{start}T00:00:00" '
        f'AND exercise.interval.civil_start_time < "{end_exclusive}T00:00:00"'
    )

    points = await _fetch_data_points(
        "exercise", filter_expr=filter_expr, page_size=200
    )
    return {
        "start_date": start,
        "end_date": end,
        "workout_count": len(points),
        "workouts": points,
    }


async def _create_data_point(
    data_type: str,
    body: dict[str, Any],
) -> dict[str, Any]:
    """Create a dataPoint in Google Health API v4."""
    token = _get_verified_token()
    url = f"{HEALTH_API_BASE}/users/me/dataTypes/{data_type}/dataPoints"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(url, headers=headers, json=body)
        if resp.status_code == 401:
            raise PermissionError(
                "Google Health API rejected the token (401). Please re-authenticate."
            )
        if resp.status_code == 403:
            raise PermissionError(
                f"Google Health API returned 403 Forbidden writing to '{data_type}'. "
                "Verify the nutrition write scope was granted (disconnect & reconnect in Gemini)."
            )
        if resp.status_code >= 400:
            raise ValueError(
                f"Google Health API returned {resp.status_code} for '{data_type}': {resp.text}"
            )
        return resp.json()


@mcp.tool
async def get_meals(
    start_date: str | None = None,
    end_date: str | None = None,
) -> dict[str, Any]:
    """
    Get logged meals / nutrition entries from Google Health for a date range (YYYY-MM-DD).
    Defaults to today and yesterday (last 2 days) if dates are omitted.
    """
    start, end = _default_date_range(start_date, end_date, default_days=2)
    end_exclusive = _next_day_iso(end)
    filter_expr = (
        f'nutrition_log.interval.civil_start_time >= "{start}T00:00:00" '
        f'AND nutrition_log.interval.civil_start_time < "{end_exclusive}T00:00:00"'
    )

    points = await _fetch_data_points(
        "nutrition-log", filter_expr=filter_expr, page_size=200
    )
    return {
        "start_date": start,
        "end_date": end,
        "meal_count": len(points),
        "meals": points,
    }


@mcp.tool
async def log_meal(
    food_name: str,
    calories_kcal: float,
    meal_type: str = "ANY_TIME",
    protein_grams: float | None = None,
    carbs_grams: float | None = None,
    fat_grams: float | None = None,
    fiber_grams: float | None = None,
    sugar_grams: float | None = None,
    eaten_at: str | None = None,
) -> dict[str, Any]:
    """
    Log a meal or food item into Google Health (nutrition-log).

    Args:
        food_name: Name/description of the meal (e.g., "Grilled Chicken Salad").
        calories_kcal: Total calories in kcal.
        meal_type: One of BREAKFAST, LUNCH, DINNER, SNACK, or ANY_TIME.
        protein_grams: Optional protein in grams.
        carbs_grams: Optional total carbohydrates in grams.
        fat_grams: Optional total fat in grams.
        fiber_grams: Optional dietary fiber in grams.
        sugar_grams: Optional total sugar in grams.
        eaten_at: Optional ISO-8601 UTC timestamp (e.g., "2026-11-19T12:30:00Z"). Defaults to now.
    """
    valid_meal_types = {"BREAKFAST", "LUNCH", "DINNER", "SNACK", "ANY_TIME"}
    normalized_meal_type = meal_type.strip().upper()
    if normalized_meal_type not in valid_meal_types:
        normalized_meal_type = "ANY_TIME"

    if eaten_at:
        start_dt = datetime.fromisoformat(eaten_at.replace("Z", "+00:00"))
        if start_dt.tzinfo is None:
            start_dt = start_dt.replace(tzinfo=timezone.utc)
        start_dt = start_dt.astimezone(timezone.utc)
    else:
        start_dt = datetime.now(timezone.utc)

    end_dt = start_dt + timedelta(minutes=15)

    nutrition_log: dict[str, Any] = {
        "interval": {
            "startTime": start_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "endTime": end_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        "foodDisplayName": food_name.strip(),
        "mealType": normalized_meal_type,
        "energy": {"kcal": round(float(calories_kcal), 1)},
    }

    if carbs_grams is not None:
        nutrition_log["totalCarbohydrate"] = {"grams": round(float(carbs_grams), 1)}
    if fat_grams is not None:
        nutrition_log["totalFat"] = {"grams": round(float(fat_grams), 1)}

    nutrients: list[dict[str, Any]] = []
    if protein_grams is not None:
        nutrients.append(
            {"nutrient": "PROTEIN", "quantity": {"grams": round(float(protein_grams), 1)}}
        )
    if fiber_grams is not None:
        nutrients.append(
            {"nutrient": "DIETARY_FIBER", "quantity": {"grams": round(float(fiber_grams), 1)}}
        )
    if sugar_grams is not None:
        nutrients.append(
            {"nutrient": "TOTAL_SUGARS", "quantity": {"grams": round(float(sugar_grams), 1)}}
        )
    if nutrients:
        nutrition_log["nutrients"] = nutrients

    created = await _create_data_point("nutrition-log", {"nutritionLog": nutrition_log})
    return {
        "status": "logged",
        "meal": created,
    }


@mcp.tool
async def log_water(
    milliliters: float,
    logged_at: str | None = None,
) -> dict[str, Any]:
    """
    Log water / hydration intake into Google Health (hydration-log).

    Args:
        milliliters: Volume of water consumed in milliliters (e.g., 500 for 500ml, ~250 for 1 cup).
        logged_at: Optional ISO-8601 UTC timestamp. Defaults to now.
    """
    if logged_at:
        start_dt = datetime.fromisoformat(logged_at.replace("Z", "+00:00"))
        if start_dt.tzinfo is None:
            start_dt = start_dt.replace(tzinfo=timezone.utc)
        start_dt = start_dt.astimezone(timezone.utc)
    else:
        start_dt = datetime.now(timezone.utc)

    end_dt = start_dt + timedelta(seconds=1)
    body = {
        "hydrationLog": {
            "interval": {
                "startTime": start_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "endTime": end_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
            "amountConsumed": {
                "milliliters": round(float(milliliters), 1),
            },
        }
    }
    created = await _create_data_point("hydration-log", body)
    return {
        "status": "logged",
        "hydration": created,
    }


@mcp.tool
async def query_health_data_type(
    data_type: str,
    filter_expr: str | None = None,
    page_size: int = 100,
) -> dict[str, Any]:
    """
    Generic read-only query against any Google Health API v4 dataType.

    Note: data_type uses hyphens (e.g., 'daily-resting-heart-rate', 'weight'),
    while filter_expr field prefixes use underscores (e.g., 'daily_resting_heart_rate.date >= "2026-11-01"').
    """
    points = await _fetch_data_points(
        data_type=data_type,
        filter_expr=filter_expr,
        page_size=min(page_size, 500),
        max_pages=1,
    )
    return {
        "data_type": data_type,
        "filter": filter_expr,
        "count": len(points),
        "data_points": points,
    }


class FilterOAuthScopesMiddleware:
    """
    Raw ASGI middleware that strips client-internal scopes (such as Gemini's
    ACCESS_VIEW_MANAGE_MCP_CONTENT, SHARE_THROUGH_MCP_CONVERSATION_INFO,
    TRIGGER_TOOLS_AND_FUNCTION) from /authorize before FastMCP's GoogleProvider
    validates and forwards them to Google OAuth.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self.allowed_scopes = set(HEALTH_SCOPES)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope.get("path") == "/authorize":
            qs = scope.get("query_string", b"").decode("utf-8", errors="ignore")
            params = parse_qsl(qs, keep_blank_values=True)
            updated_params: list[tuple[str, str]] = []
            changed = False

            for key, value in params:
                if key == "scope":
                    filtered = [s for s in value.split() if s in self.allowed_scopes]
                    if not filtered:
                        filtered = list(HEALTH_SCOPES)
                    new_value = " ".join(filtered)
                    if new_value != value:
                        changed = True
                    updated_params.append((key, new_value))
                else:
                    updated_params.append((key, value))

            if changed:
                scope = dict(scope)
                scope["query_string"] = urlencode(updated_params).encode("utf-8")

        await self.app(scope, receive, send)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    app = mcp.http_app(
        path="/mcp",
        stateless_http=True,
        middleware=[Middleware(FilterOAuthScopesMiddleware)],
    )
    uvicorn.run(app, host="0.0.0.0", port=port)

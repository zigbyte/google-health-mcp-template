"""
Google Health MCP Bridge for Gemini (hosted on Google Cloud Run).

Exposes read-only tools backed by the Google Health API v4
(https://health.googleapis.com/v4) over Streamable HTTP using FastMCP
and Google OAuth 2.0.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import time
import weakref
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import parse_qsl, urlencode
from zoneinfo import ZoneInfo

import httpx
import uvicorn
from cryptography.fernet import Fernet
from fastmcp import FastMCP
from fastmcp.server.auth.jwt_issuer import derive_jwt_key
from fastmcp.server.auth.providers.google import GoogleProvider
from fastmcp.server.dependencies import get_access_token
from key_value.aio.adapters.pydantic import PydanticAdapter
from key_value.aio.wrappers.encryption import FernetEncryptionWrapper
from mcp.server.auth.provider import AccessToken, RefreshToken, TokenError
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import BaseModel
from starlette.middleware import Middleware
from starlette.types import ASGIApp, Receive, Scope, Send

logger = logging.getLogger(__name__)

HEALTH_API_BASE = "https://health.googleapis.com/v4"
FASTMCP_ACCESS_TOKEN_EXPIRY_SECONDS = 2_592_000  # 30 days
TOKEN_EXPIRY_THRESHOLD_SECONDS = 300  # Proactively refresh upstream 5m before expiry
TOKEN_CACHE_TTL_SECONDS = 300  # Cache Google tokeninfo checks for 5m
REFRESH_GRACE_PERIOD_SECONDS = 300  # 5-minute idempotent refresh rotation grace window

HEALTH_SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/googlehealth.activity_and_fitness.readonly",
    "https://www.googleapis.com/auth/googlehealth.health_metrics_and_measurements.readonly",
    "https://www.googleapis.com/auth/googlehealth.sleep.readonly",
    "https://www.googleapis.com/auth/googlehealth.nutrition.readonly",
    "https://www.googleapis.com/auth/googlehealth.nutrition.writeonly",
]


def _hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class _RefreshGraceEntry(BaseModel):
    client_id: str
    scopes: list[str]
    expires_at: int
    access_token: str
    token_type: str = "Bearer"
    expires_in: int | None = None
    refresh_token: str | None = None
    scope: str | None = None


class _RefreshGracePointer(BaseModel):
    old_token_hash: str


class GracefulGoogleProvider(GoogleProvider):
    """GoogleProvider with an idempotent refresh-token rotation grace window.

    When a client retries POST /token with an already-rotated refresh token
    (for example after a cold-start timeout), this provider serves the exact
    same OAuthToken response for ``refresh_grace_period_seconds`` without
    re-calling Google or rotating a second time.
    """

    def __init__(
        self,
        *,
        refresh_grace_period_seconds: int = REFRESH_GRACE_PERIOD_SECONDS,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._refresh_grace_seconds = max(0, int(refresh_grace_period_seconds))
        self._grace_locks: weakref.WeakValueDictionary[str, asyncio.Lock] = (
            weakref.WeakValueDictionary()
        )

        grace_encryption_key = derive_jwt_key(
            high_entropy_material=self._jwt_signing_key.decode("utf-8"),
            salt="fastmcp-refresh-grace-encryption-key",
        )
        encrypted_grace_kv = FernetEncryptionWrapper(
            key_value=self._client_storage,
            fernet=Fernet(key=grace_encryption_key),
            raise_on_decryption_error=False,
        )
        self._refresh_grace_store: PydanticAdapter[_RefreshGraceEntry] = (
            PydanticAdapter[_RefreshGraceEntry](
                key_value=encrypted_grace_kv,
                pydantic_model=_RefreshGraceEntry,
                default_collection="mcp-refresh-token-grace",
                raise_on_validation_error=False,
            )
        )
        self._refresh_grace_reverse_store: PydanticAdapter[_RefreshGracePointer] = (
            PydanticAdapter[_RefreshGracePointer](
                key_value=encrypted_grace_kv,
                pydantic_model=_RefreshGracePointer,
                default_collection="mcp-refresh-token-grace-rev",
                raise_on_validation_error=False,
            )
        )

    def _get_grace_lock(self, token_hash: str) -> asyncio.Lock:
        lock = self._grace_locks.get(token_hash)
        if lock is None:
            lock = asyncio.Lock()
            self._grace_locks[token_hash] = lock
        return lock

    async def load_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: str,
    ) -> RefreshToken | None:
        token_hash = _hash_refresh_token(refresh_token)
        lock = self._get_grace_lock(token_hash)
        async with lock:
            token = await super().load_refresh_token(client, refresh_token)
            if token is not None or self._refresh_grace_seconds <= 0:
                return token

            grace = await self._refresh_grace_store.get(key=token_hash)
            if grace is None:
                return None
            if time.time() > grace.expires_at:
                await self._refresh_grace_store.delete(key=token_hash)
                return None
            if grace.client_id != client.client_id:
                logger.warning(
                    "Grace refresh token client_id mismatch: expected %s, got %s",
                    client.client_id,
                    grace.client_id,
                )
                return None

            return RefreshToken(
                token=refresh_token,
                client_id=grace.client_id,
                scopes=grace.scopes,
                expires_at=grace.expires_at,
            )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        if self._refresh_grace_seconds <= 0:
            return await super().exchange_refresh_token(client, refresh_token, scopes)

        token_hash = _hash_refresh_token(refresh_token.token)
        lock = self._get_grace_lock(token_hash)
        async with lock:
            grace = await self._refresh_grace_store.get(key=token_hash)
            if grace is not None:
                if time.time() > grace.expires_at:
                    await self._refresh_grace_store.delete(key=token_hash)
                    raise TokenError("invalid_grant", "Refresh token grace window expired")
                if grace.client_id != client.client_id:
                    raise TokenError("invalid_grant", "Refresh token client mismatch")
                if scopes and not set(scopes).issubset(set(grace.scopes)):
                    raise TokenError(
                        "invalid_scope",
                        "Requested scopes exceed original refresh grant",
                    )

                logger.info(
                    "Serving idempotent grace-window refresh response for client=%s (token_hash=%s)",
                    client.client_id,
                    token_hash[:8],
                )
                return OAuthToken(
                    access_token=grace.access_token,
                    token_type=grace.token_type,
                    expires_in=grace.expires_in,
                    refresh_token=grace.refresh_token,
                    scope=grace.scope,
                )

            new_token = await super().exchange_refresh_token(
                client, refresh_token, scopes
            )

            grace_expires_at = int(time.time()) + self._refresh_grace_seconds
            entry = _RefreshGraceEntry(
                client_id=client.client_id or "",
                scopes=list(refresh_token.scopes),
                expires_at=grace_expires_at,
                access_token=new_token.access_token,
                token_type=new_token.token_type,
                expires_in=new_token.expires_in,
                refresh_token=new_token.refresh_token,
                scope=new_token.scope,
            )
            await self._refresh_grace_store.put(
                key=token_hash,
                value=entry,
                ttl=self._refresh_grace_seconds,
            )
            if new_token.refresh_token:
                await self._refresh_grace_reverse_store.put(
                    key=_hash_refresh_token(new_token.refresh_token),
                    value=_RefreshGracePointer(old_token_hash=token_hash),
                    ttl=self._refresh_grace_seconds,
                )
            return new_token

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        if isinstance(token, RefreshToken):
            token_hash = _hash_refresh_token(token.token)
            await self._refresh_grace_store.delete(key=token_hash)
            pointer = await self._refresh_grace_reverse_store.get(key=token_hash)
            if pointer is not None:
                await self._refresh_grace_store.delete(key=pointer.old_token_hash)
                await self._refresh_grace_reverse_store.delete(key=token_hash)
        await super().revoke_token(token)


def _use_firestore_enabled() -> bool:
    return os.environ.get("USE_FIRESTORE", "").strip().lower() in ("1", "true", "yes")


def _build_client_storage():
    """Return a Firestore-backed AsyncKeyValue store when USE_FIRESTORE=true."""
    if not _use_firestore_enabled():
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
    if _use_firestore_enabled() and not jwt_signing_key:
        raise RuntimeError(
            "JWT_SIGNING_KEY must be set when USE_FIRESTORE=true so tokens "
            "and encrypted refresh grace records remain valid across restarts."
        )

    return GracefulGoogleProvider(
        client_id=client_id,
        client_secret=client_secret,
        base_url=base_url,
        redirect_path="/auth/callback",
        required_scopes=HEALTH_SCOPES,
        jwt_signing_key=jwt_signing_key,
        client_storage=_build_client_storage(),
        fastmcp_access_token_expiry_seconds=FASTMCP_ACCESS_TOKEN_EXPIRY_SECONDS,
        token_expiry_threshold_seconds=TOKEN_EXPIRY_THRESHOLD_SECONDS,
        cache_ttl_seconds=TOKEN_CACHE_TTL_SECONDS,
        refresh_grace_period_seconds=REFRESH_GRACE_PERIOD_SECONDS,
    )


READ_ONLY_ANNOTATIONS = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
}
WRITE_ANNOTATIONS = {
    "readOnlyHint": False,
    "destructiveHint": False,
    "idempotentHint": False,
    "openWorldHint": False,
}
DELETE_ANNOTATIONS = {
    "readOnlyHint": False,
    "destructiveHint": True,
    "idempotentHint": True,
    "openWorldHint": False,
}

STRENGTH_COLLECTION = os.environ.get("STRENGTH_COLLECTION", "strength_logs")
MINDFULNESS_COLLECTION = os.environ.get("MINDFULNESS_COLLECTION", "mindfulness_logs")
CHECKIN_COLLECTION = os.environ.get("CHECKIN_COLLECTION", "daily_checkins")
PROFILE_COLLECTION = os.environ.get("PROFILE_COLLECTION", "user_profile")
USER_TIMEZONE_NAME = os.environ.get("USER_TIMEZONE", "UTC").strip() or "UTC"
USER_TZ = ZoneInfo(USER_TIMEZONE_NAME)
USER_SEX = os.environ.get("USER_SEX", "").strip().lower()
USER_HEIGHT_CM_RAW = os.environ.get("USER_HEIGHT_CM", "").strip()
USER_BIRTH_YEAR_RAW = os.environ.get("USER_BIRTH_YEAR", "").strip()
USER_GOAL_WEIGHT_LBS_RAW = os.environ.get("USER_GOAL_WEIGHT_LBS", "").strip()
USER_GOAL_OBJECTIVE_DEFAULT = (
    os.environ.get("USER_GOAL_OBJECTIVE", "").strip()
    or "Reach optimal lean athletic weight with shredded muscle retention"
)
_firestore_client: Any = None
_goals_cache: dict[str, Any] | None = None
_goals_cache_ts: float = 0.0
_GOALS_CACHE_TTL_SEC = 60.0

VALID_WEIGHT_MODES = ("optimal", "custom")
VALID_PACE_MODES = ("optimal", "slow", "normal", "medium_fast", "fast", "by_date")
PACE_PRESET_PCT_BW_WK: dict[str, float] = {
    "slow": 0.35,
    "normal": 0.55,
    "medium_fast": 0.75,
    "fast": 1.00,
}


def _parse_optional_float(raw: str) -> float | None:
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError:
        return None


def _parse_optional_int(raw: str) -> int | None:
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _build_user_profile(
    latest_weight_kg: float | None = None,
    latest_waist_in: float | None = None,
) -> dict[str, Any]:
    """Build the user's static demographic/anthropometric profile from env vars."""
    profile: dict[str, Any] = {"timezone": USER_TIMEZONE_NAME}

    if USER_SEX:
        profile["sex"] = USER_SEX

    height_cm = _parse_optional_float(USER_HEIGHT_CM_RAW)
    if height_cm and height_cm > 0:
        total_inches = height_cm / 2.54
        feet = int(total_inches // 12)
        inches = round(total_inches - feet * 12, 1)
        profile["height_cm"] = round(height_cm, 1)
        profile["height_in"] = round(total_inches, 1)
        profile["height_ft_in"] = f"{feet}'{inches}\""

    birth_year = _parse_optional_int(USER_BIRTH_YEAR_RAW)
    age: int | None = None
    if birth_year and 1900 <= birth_year <= datetime.now(USER_TZ).year:
        age = datetime.now(USER_TZ).year - birth_year
        profile["birth_year"] = birth_year
        profile["age"] = age
        profile["estimated_max_hr_bpm"] = round(208 - 0.7 * age)

    goal_weight_lbs = _parse_optional_float(USER_GOAL_WEIGHT_LBS_RAW)
    if goal_weight_lbs and goal_weight_lbs > 0:
        profile["goal_weight_lbs"] = round(goal_weight_lbs, 1)
        profile["goal_weight_kg"] = round(goal_weight_lbs / 2.20462, 2)

    if latest_weight_kg and height_cm and height_cm > 0:
        height_m = height_cm / 100.0
        profile["bmi"] = round(latest_weight_kg / (height_m * height_m), 1)
        if age is not None and USER_SEX in ("female", "male"):
            bmr_offset = -161 if USER_SEX == "female" else 5
            profile["mifflin_st_jeor_bmr_kcal"] = round(
                10 * latest_weight_kg + 6.25 * height_cm - 5 * age + bmr_offset
            )

    if latest_waist_in and height_cm and height_cm > 0:
        profile["waist_to_height_ratio"] = round((latest_waist_in * 2.54) / height_cm, 3)

    return profile


def _default_goals_from_env() -> dict[str, Any]:
    env_weight = _parse_optional_float(USER_GOAL_WEIGHT_LBS_RAW)
    has_custom = bool(env_weight and env_weight > 0)
    return {
        "goal_objective": USER_GOAL_OBJECTIVE_DEFAULT,
        "target_weight_mode": "custom" if has_custom else "optimal",
        "custom_target_weight_lbs": round(env_weight, 1) if has_custom and env_weight else None,
        "pace_mode": "optimal",
        "target_date": None,
        "milestone_phase": 1,
        "milestone_target_lbs": None,
        "milestone_target_waist_in": None,
        "milestone_approved": False,
        "notes": "",
        "updated_at": None,
        "updated_by": "env_default",
    }


async def _load_user_goals(force_refresh: bool = False) -> tuple[dict[str, Any], str]:
    """Load mutable user goals from Firestore (cached 60s), falling back to env defaults."""
    global _goals_cache, _goals_cache_ts
    now = time.time()
    if not force_refresh and _goals_cache is not None and (now - _goals_cache_ts) < _GOALS_CACHE_TTL_SEC:
        return dict(_goals_cache), str(_goals_cache.get("_source", "firestore"))

    defaults = _default_goals_from_env()
    try:
        db = _get_firestore_client()
        snap = await db.collection(PROFILE_COLLECTION).document("goals").get()
        if snap.exists:
            data = snap.to_dict() or {}
            merged = {**defaults, **{k: v for k, v in data.items() if k in defaults}}
            merged["_source"] = "firestore"
            _goals_cache = dict(merged)
            _goals_cache_ts = now
            return {k: v for k, v in merged.items() if k != "_source"}, "firestore"
    except Exception as exc:
        logger.warning("Failed to load user_profile/goals from Firestore: %s", exc)

    defaults_cached = {**defaults, "_source": "env_default"}
    _goals_cache = dict(defaults_cached)
    _goals_cache_ts = now
    return defaults, "env_default"


def _compute_goal_targets(
    goals: dict[str, Any],
    latest_weight_kg: float | None = None,
    latest_waist_in: float | None = None,
) -> dict[str, Any]:
    """Compute objective physiological anchors, Phase milestone, and safe pace targets."""
    height_cm = _parse_optional_float(USER_HEIGHT_CM_RAW)
    is_male = USER_SEX == "male"
    latest_weight_lbs = round(latest_weight_kg * 2.20462, 1) if latest_weight_kg else None

    anchors: dict[str, Any] = {
        "target_whtr": [0.45, 0.50] if is_male else [0.44, 0.49],
        "target_bf_pct": [10, 15] if is_male else [18, 22],
    }
    if height_cm and height_cm > 0:
        h_m = height_cm / 100.0
        anchors["bmi_healthy_lbs"] = [
            round(18.5 * h_m * h_m * 2.20462),
            round(24.9 * h_m * h_m * 2.20462),
        ]
        recomp_bmi_lo, recomp_bmi_hi = (21.5, 25.5) if is_male else (20.6, 24.7)
        anchors["athletic_recomp_lbs"] = [
            round(recomp_bmi_lo * h_m * h_m * 2.20462),
            round(recomp_bmi_hi * h_m * h_m * 2.20462),
        ]
        anchors["target_waist_in"] = [
            round(anchors["target_whtr"][0] * height_cm / 2.54, 1),
            round(anchors["target_whtr"][1] * height_cm / 2.54, 1),
        ]
        if latest_waist_in and latest_waist_in > 0:
            anchors["current_whtr"] = round((latest_waist_in * 2.54) / height_cm, 3)

    # Phase milestone (explicit or auto-proposed -10% BW checkpoint)
    phase = int(goals.get("milestone_phase") or 1)
    m_lbs = goals.get("milestone_target_lbs")
    m_waist = goals.get("milestone_target_waist_in")
    m_approved = bool(goals.get("milestone_approved", False))
    auto_proposed = False
    recomp_hi = (anchors.get("athletic_recomp_lbs") or [None, None])[1]
    waist_hi = (anchors.get("target_waist_in") or [None, None])[1]

    if m_lbs is None and latest_weight_lbs is not None:
        if recomp_hi is None or latest_weight_lbs > recomp_hi + 5:
            m_lbs = float(round(latest_weight_lbs * 0.90))
            auto_proposed = True
    if m_waist is None and latest_waist_in is not None and waist_hi is not None:
        if latest_waist_in > waist_hi + 1.0:
            m_waist = round((latest_waist_in + waist_hi) / 2.0, 1)
            auto_proposed = True

    milestone = {
        "phase": phase,
        "target_lbs": round(float(m_lbs), 1) if m_lbs is not None else None,
        "target_waist_in": round(float(m_waist), 1) if m_waist is not None else None,
        "approved": m_approved if not auto_proposed else False,
        "auto_proposed": auto_proposed,
    }

    # Active target weight for rate / by_date math
    weight_mode = goals.get("target_weight_mode") or "optimal"
    active_target_lbs: float | None = None
    if weight_mode == "custom" and goals.get("custom_target_weight_lbs"):
        active_target_lbs = float(goals["custom_target_weight_lbs"])
    elif milestone["target_lbs"] is not None:
        active_target_lbs = float(milestone["target_lbs"])
    elif recomp_hi is not None:
        active_target_lbs = float(recomp_hi)

    # Pace & deficit computation
    pace_mode = goals.get("pace_mode") or "optimal"
    current_whtr = anchors.get("current_whtr")
    by_date_safety_flag: str | None = None
    weeks_remaining: float | None = None

    if pace_mode == "optimal":
        if current_whtr is not None:
            active_pct = 0.80 if current_whtr > 0.55 else (0.60 if current_whtr >= 0.50 else 0.45)
        else:
            active_pct = 0.70
    elif pace_mode in PACE_PRESET_PCT_BW_WK:
        active_pct = PACE_PRESET_PCT_BW_WK[pace_mode]
    elif pace_mode == "by_date" and goals.get("target_date") and latest_weight_lbs and active_target_lbs:
        try:
            tgt_dt = _parse_date(str(goals["target_date"])).date()
            today_dt = datetime.now(USER_TZ).date()
            days_left = max(1, (tgt_dt - today_dt).days)
            weeks_remaining = round(days_left / 7.0, 1)
            lbs_to_lose = max(0.0, latest_weight_lbs - active_target_lbs)
            req_lbs_wk = lbs_to_lose / max(weeks_remaining, 0.5)
            active_pct = round((req_lbs_wk / latest_weight_lbs) * 100.0, 2)
            if active_pct > 1.0:
                by_date_safety_flag = "exceeds_lbm_safe_rate"
        except Exception:
            active_pct = 0.70
    else:
        active_pct = 0.70

    target_lbs_per_wk = (
        round((active_pct / 100.0) * latest_weight_lbs, 2) if latest_weight_lbs else None
    )
    daily_deficit_kcal = round(target_lbs_per_wk * 500) if target_lbs_per_wk is not None else None

    ref_protein_lbs = recomp_hi or active_target_lbs or (latest_weight_lbs or 150.0)
    protein_g_min = round(2.0 * (float(ref_protein_lbs) / 2.20462))

    return {
        "weight_mode": weight_mode,
        "pace_mode": pace_mode,
        "anchors": anchors,
        "milestone": milestone,
        "pace": {
            "preset_pct_bw_wk": PACE_PRESET_PCT_BW_WK,
            "active_pct_bw_wk": round(active_pct, 2),
            "target_lbs_per_wk": target_lbs_per_wk,
            "daily_deficit_kcal": daily_deficit_kcal,
            "weeks_remaining": weeks_remaining,
            "by_date_safety_flag": by_date_safety_flag,
        },
        "nutrition_floors": {
            "protein_g_min": protein_g_min,
            "kcal_floor": 1600 if is_male else 1350,
        },
    }


def _compact_goals_summary(
    goals: dict[str, Any], computed: dict[str, Any]
) -> dict[str, Any]:
    """Compact ~55-token goal summary auto-attached to cut & body-comp tools."""
    anchors = computed.get("anchors") or {}
    milestone = computed.get("milestone") or {}
    pace = computed.get("pace") or {}
    floors = computed.get("nutrition_floors") or {}
    return {
        "objective": goals.get("goal_objective"),
        "weight_mode": goals.get("target_weight_mode"),
        "custom_target_lbs": goals.get("custom_target_weight_lbs"),
        "target_lbs_range": anchors.get("athletic_recomp_lbs"),
        "target_waist_in": anchors.get("target_waist_in"),
        "milestone": milestone,
        "pace_mode": goals.get("pace_mode"),
        "target_lbs_per_wk": pace.get("target_lbs_per_wk"),
        "daily_deficit_kcal": pace.get("daily_deficit_kcal"),
        "protein_g_min": floors.get("protein_g_min"),
        "target_date": goals.get("target_date"),
        "safety_flag": pace.get("by_date_safety_flag"),
    }


def _get_firestore_client() -> Any:
    """Lazily initialize the async Firestore client for strength logs."""
    global _firestore_client
    if _firestore_client is None:
        from google.cloud import firestore

        database = os.environ.get("FIRESTORE_DATABASE", "(default)")
        _firestore_client = firestore.AsyncClient(database=database)
    return _firestore_client


mcp = FastMCP(
    name="Google Health Bridge",
    instructions=(
        "Bridge to the user's Google Health API v4 data and personal Firestore logs: "
        "read user profile (sex, height, birth year, age, timezone), steps, sleep, heart rate, "
        "recovery vitals (RHR, respiratory rate, SpO2, HRV), daily energy/TDEE & active zone minutes, "
        "body composition, hydration, meals, exercises, daily check-ins, mindfulness, strength logs, "
        "and combined daily cut summaries; log meals, water intake, daily check-ins, mindfulness, "
        "and strength training sets. Dates use YYYY-MM-DD format."
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
    today = datetime.now(USER_TZ).date()
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


def _utc_bounds_for_local_dates(start_date: str, end_date: str) -> tuple[str, str]:
    """Convert inclusive local YYYY-MM-DD bounds to [start_utc, end_exclusive_utc) ISO strings."""
    s = _parse_date(start_date).replace(tzinfo=USER_TZ)
    e = (_parse_date(end_date) + timedelta(days=1)).replace(tzinfo=USER_TZ)
    return (
        s.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        e.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


def _iso_to_local_date(ts: str) -> str:
    """Convert an ISO-8601 timestamp string into a YYYY-MM-DD date in USER_TZ."""
    if not ts:
        return "unknown"
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(USER_TZ).date().isoformat()
    except ValueError:
        return ts[:10] if len(ts) >= 10 else "unknown"


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


async def _rollup_data_points(
    data_type: str,
    start_date: str,
    end_date: str,
    window_size: str = "86400s",
) -> list[dict[str, Any]]:
    """Query Google Health API v4 dataPoints:rollUp, chunking into <=14-day windows."""
    token = _get_verified_token()
    url = f"{HEALTH_API_BASE}/users/me/dataTypes/{data_type}/dataPoints:rollUp"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    start_dt = _parse_date(start_date).date()
    end_exclusive_dt = _parse_date(end_date).date() + timedelta(days=1)

    rollups: list[dict[str, Any]] = []
    async with httpx.AsyncClient(timeout=15.0) as client:
        cursor = start_dt
        while cursor < end_exclusive_dt:
            chunk_end = min(end_exclusive_dt, cursor + timedelta(days=14))
            chunk_start_utc = (
                datetime(cursor.year, cursor.month, cursor.day, tzinfo=USER_TZ)
                .astimezone(timezone.utc)
                .strftime("%Y-%m-%dT%H:%M:%SZ")
            )
            chunk_end_utc = (
                datetime(chunk_end.year, chunk_end.month, chunk_end.day, tzinfo=USER_TZ)
                .astimezone(timezone.utc)
                .strftime("%Y-%m-%dT%H:%M:%SZ")
            )
            page_token: str | None = None
            for _ in range(3):
                body: dict[str, Any] = {
                    "range": {
                        "startTime": chunk_start_utc,
                        "endTime": chunk_end_utc,
                    },
                    "windowSize": window_size,
                    "pageSize": 14,
                }
                if page_token:
                    body["pageToken"] = page_token

                resp = await client.post(url, headers=headers, json=body)
                if resp.status_code == 401:
                    raise PermissionError(
                        "Google Health API rejected the token (401). Please re-authenticate."
                    )
                if resp.status_code == 403:
                    raise PermissionError(
                        f"Google Health API returned 403 Forbidden for '{data_type}:rollUp'."
                    )
                resp.raise_for_status()

                payload = resp.json()
                rollups.extend(payload.get("rollupDataPoints", []))
                page_token = payload.get("nextPageToken")
                if not page_token:
                    break
            cursor = chunk_end

    return rollups


def _format_proto_date(raw: Any) -> str:
    if isinstance(raw, dict) and raw.get("year"):
        return f"{int(raw['year']):04d}-{int(raw.get('month', 1)):02d}-{int(raw.get('day', 1)):02d}"
    if isinstance(raw, str) and len(raw) >= 10:
        return raw[:10]
    return "unknown"


@mcp.tool(annotations=READ_ONLY_ANNOTATIONS)
async def get_steps(
    start_date: str | None = None,
    end_date: str | None = None,
) -> dict[str, Any]:
    """
    Get reconciled daily step totals from Google Health for a date range (YYYY-MM-DD),
    bucketed in the user's local timezone using dataPoints:rollUp to avoid multi-source double-counting.
    Defaults to the last 7 days if dates are omitted.
    """
    start, end = _default_date_range(start_date, end_date, default_days=7)
    rollups = await _rollup_data_points("steps", start, end, window_size="86400s")

    daily_totals: dict[str, int] = defaultdict(int)
    for rp in rollups:
        ts = rp.get("startTime") or rp.get("range", {}).get("startTime") or ""
        day = _iso_to_local_date(ts) if ts else "unknown"
        steps_obj = rp.get("steps") or {}
        count = steps_obj.get("countSum") or steps_obj.get("count") or 0
        daily_totals[day] += int(count)

    ordered = dict(sorted(daily_totals.items()))
    return {
        "timezone": USER_TIMEZONE_NAME,
        "start_date": start,
        "end_date": end,
        "total_steps": sum(ordered.values()),
        "daily_steps": ordered,
        "rollup_buckets_fetched": len(rollups),
        "reconciled": True,
    }


@mcp.tool(annotations=READ_ONLY_ANNOTATIONS)
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


@mcp.tool(annotations=READ_ONLY_ANNOTATIONS)
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
    start_utc, end_utc = _utc_bounds_for_local_dates(start, end)
    filter_expr = (
        f'heart_rate.sample_time.physical_time >= "{start_utc}" '
        f'AND heart_rate.sample_time.physical_time < "{end_utc}"'
    )

    points = await _fetch_data_points(
        "heart-rate", filter_expr=filter_expr, page_size=5000
    )

    by_day: dict[str, list[float]] = defaultdict(list)
    for pt in points:
        hr = pt.get("heartRate", {})
        sample_time = hr.get("sampleTime", {})
        ts = sample_time.get("physicalTime") or ""
        day = _iso_to_local_date(ts) if ts else _format_proto_date(sample_time.get("civilTime", {}).get("date"))
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
        "timezone": USER_TIMEZONE_NAME,
        "start_date": start,
        "end_date": end,
        "daily_summary": daily_summary,
        "total_samples_fetched": len(points),
    }
    if include_samples:
        result["samples"] = points[:200]
    return result


@mcp.tool(annotations=READ_ONLY_ANNOTATIONS)
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


@mcp.tool(annotations=READ_ONLY_ANNOTATIONS)
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


@mcp.tool(annotations=READ_ONLY_ANNOTATIONS)
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


@mcp.tool(annotations=WRITE_ANNOTATIONS)
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


@mcp.tool(annotations=WRITE_ANNOTATIONS)
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


@mcp.tool(annotations=READ_ONLY_ANNOTATIONS)
async def get_hydration(
    start_date: str | None = None,
    end_date: str | None = None,
) -> dict[str, Any]:
    """
    Get logged water / hydration intake from Google Health for a date range (YYYY-MM-DD).
    Defaults to today and yesterday (last 2 days). Returns daily totals in mL and fl oz.
    """
    start, end = _default_date_range(start_date, end_date, default_days=2)
    end_exclusive = _next_day_iso(end)
    filter_expr = (
        f'hydration_log.interval.civil_start_time >= "{start}T00:00:00" '
        f'AND hydration_log.interval.civil_start_time < "{end_exclusive}T00:00:00"'
    )

    points = await _fetch_data_points(
        "hydration-log", filter_expr=filter_expr, page_size=200
    )

    daily_ml: dict[str, float] = defaultdict(float)
    logs: list[dict[str, Any]] = []
    for pt in points:
        hl = pt.get("hydrationLog", {})
        interval = hl.get("interval", {})
        civil_date = interval.get("civilStartTime", {}).get("date")
        day = _format_proto_date(civil_date or interval.get("startTime"))
        ml = float(hl.get("amountConsumed", {}).get("milliliters") or 0)
        if ml > 0:
            daily_ml[day] += ml
            logs.append(
                {
                    "name": pt.get("name"),
                    "date": day,
                    "start_time": interval.get("startTime"),
                    "milliliters": round(ml, 1),
                    "fl_oz": round(ml / 29.5735, 1),
                }
            )

    daily_totals = {
        day: {
            "milliliters": round(ml, 1),
            "liters": round(ml / 1000.0, 2),
            "fl_oz": round(ml / 29.5735, 1),
        }
        for day, ml in sorted(daily_ml.items())
    }
    total_ml = round(sum(daily_ml.values()), 1)
    return {
        "start_date": start,
        "end_date": end,
        "total_milliliters": total_ml,
        "total_fl_oz": round(total_ml / 29.5735, 1),
        "daily_totals": daily_totals,
        "log_count": len(logs),
        "logs": logs,
    }


@mcp.tool(annotations=READ_ONLY_ANNOTATIONS)
async def get_recovery_vitals(
    start_date: str | None = None,
    end_date: str | None = None,
) -> dict[str, Any]:
    """
    Get dedicated daily recovery vitals from Google Health in one call:
    Resting Heart Rate (bpm), Respiratory Rate (breaths/min), SpO2 (%), and HRV (RMSSD ms).
    Defaults to the last 14 days.
    """
    start, end = _default_date_range(start_date, end_date, default_days=14)
    end_exclusive = _next_day_iso(end)

    async def _safe_daily(dt: str) -> list[dict[str, Any]]:
        prefix = dt.replace("-", "_")
        flt = f'{prefix}.date >= "{start}" AND {prefix}.date < "{end_exclusive}"'
        try:
            return await _fetch_data_points(dt, filter_expr=flt, page_size=100, max_pages=1)
        except Exception:
            return []

    rhr_pts, resp_pts, spo2_pts, hrv_pts = await asyncio.gather(
        _safe_daily("daily-resting-heart-rate"),
        _safe_daily("daily-respiratory-rate"),
        _safe_daily("daily-oxygen-saturation"),
        _safe_daily("daily-heart-rate-variability"),
    )

    by_day: dict[str, dict[str, Any]] = defaultdict(dict)

    for pt in rhr_pts:
        obj = pt.get("dailyRestingHeartRate", {})
        day = _format_proto_date(obj.get("date"))
        bpm = obj.get("beatsPerMinute")
        if bpm is not None:
            by_day[day]["resting_hr_bpm"] = round(float(bpm), 1)

    for pt in resp_pts:
        obj = pt.get("dailyRespiratoryRate", {})
        day = _format_proto_date(obj.get("date"))
        rate = (
            obj.get("breathsPerMinute")
            or obj.get("averageBreathsPerMinute")
            or obj.get("fullSleepSummary", {}).get("breathsPerMinute")
        )
        if rate is not None:
            by_day[day]["respiratory_rate_brpm"] = round(float(rate), 1)
        elif obj:
            by_day[day]["respiratory_rate_raw"] = obj

    for pt in spo2_pts:
        obj = pt.get("dailyOxygenSaturation", {})
        day = _format_proto_date(obj.get("date"))
        pct = obj.get("averagePercentage") or obj.get("averageSaturationPercentage")
        if pct is not None:
            by_day[day]["spo2_pct"] = round(float(pct), 1)

    for pt in hrv_pts:
        obj = pt.get("dailyHeartRateVariability", {})
        day = _format_proto_date(obj.get("date"))
        ms = obj.get("averageHeartRateVariabilityMillis") or obj.get("rmssdMillis")
        if ms is not None:
            by_day[day]["hrv_rmssd_ms"] = round(float(ms), 1)
        non_rem = obj.get("nonRemHeartRateBeatsPerMinute")
        if non_rem is not None:
            by_day[day]["non_rem_hr_bpm"] = round(float(non_rem), 1)

    ordered = dict(sorted(by_day.items()))
    return {
        "start_date": start,
        "end_date": end,
        "days_with_data": len(ordered),
        "daily_vitals": ordered,
    }


@mcp.tool(annotations=READ_ONLY_ANNOTATIONS)
async def get_daily_energy(
    start_date: str | None = None,
    end_date: str | None = None,
) -> dict[str, Any]:
    """
    Get daily Total Daily Energy Expenditure (TDEE in kcal via total-calories:rollUp),
    Active Zone Minutes (AZM), and Active Minutes for a date range (YYYY-MM-DD).
    Defaults to the last 7 days.
    """
    start, end = _default_date_range(start_date, end_date, default_days=7)
    start_utc, end_utc = _utc_bounds_for_local_dates(start, end)

    async def _safe_azm() -> list[dict[str, Any]]:
        flt = (
            f'active_zone_minutes.interval.start_time >= "{start_utc}" '
            f'AND active_zone_minutes.interval.start_time < "{end_utc}"'
        )
        try:
            return await _fetch_data_points(
                "active-zone-minutes", filter_expr=flt, page_size=2000, max_pages=2
            )
        except Exception:
            return []

    async def _safe_active() -> list[dict[str, Any]]:
        flt = (
            f'active_minutes.interval.start_time >= "{start_utc}" '
            f'AND active_minutes.interval.start_time < "{end_utc}"'
        )
        try:
            return await _fetch_data_points(
                "active-minutes", filter_expr=flt, page_size=2000, max_pages=2
            )
        except Exception:
            return []

    cal_rollups, azm_pts, active_pts = await asyncio.gather(
        _rollup_data_points("total-calories", start, end, window_size="86400s"),
        _safe_azm(),
        _safe_active(),
    )

    by_day: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"tdee_kcal": 0.0, "active_zone_minutes": 0, "active_minutes": 0}
    )

    for rp in cal_rollups:
        ts = rp.get("startTime") or rp.get("range", {}).get("startTime") or ""
        day = _iso_to_local_date(ts)
        tc = rp.get("totalCalories", {})
        kcal = float(tc.get("kcalSum") or tc.get("kcal") or 0)
        by_day[day]["tdee_kcal"] = round(by_day[day]["tdee_kcal"] + kcal, 1)

    for pt in azm_pts:
        obj = pt.get("activeZoneMinutes", {})
        ts = obj.get("interval", {}).get("startTime") or ""
        day = _iso_to_local_date(ts)
        mins = int(obj.get("activeZoneMinutes") or obj.get("minutes") or 0)
        by_day[day]["active_zone_minutes"] += mins

    for pt in active_pts:
        obj = pt.get("activeMinutes", {})
        ts = obj.get("interval", {}).get("startTime") or ""
        day = _iso_to_local_date(ts)
        mins = int(obj.get("minutes") or 0)
        by_day[day]["active_minutes"] += mins

    ordered = dict(sorted(by_day.items()))
    return {
        "timezone": USER_TIMEZONE_NAME,
        "start_date": start,
        "end_date": end,
        "daily_energy": ordered,
    }


@mcp.tool(annotations=READ_ONLY_ANNOTATIONS)
async def get_body_composition(
    start_date: str | None = None,
    end_date: str | None = None,
) -> dict[str, Any]:
    """
    Get weight (lbs and kg) and body fat percentage records from Google Health.
    Defaults to the last 30 days.
    """
    start, end = _default_date_range(start_date, end_date, default_days=30)
    start_utc, end_utc = _utc_bounds_for_local_dates(start, end)

    weight_flt = (
        f'weight.sample_time.physical_time >= "{start_utc}" '
        f'AND weight.sample_time.physical_time < "{end_utc}"'
    )
    bf_flt = (
        f'body_fat.sample_time.physical_time >= "{start_utc}" '
        f'AND body_fat.sample_time.physical_time < "{end_utc}"'
    )

    async def _safe_bf() -> list[dict[str, Any]]:
        try:
            return await _fetch_data_points("body-fat", filter_expr=bf_flt, page_size=200, max_pages=1)
        except Exception:
            return []

    weight_pts, bf_pts = await asyncio.gather(
        _fetch_data_points("weight", filter_expr=weight_flt, page_size=200, max_pages=1),
        _safe_bf(),
    )

    weights: list[dict[str, Any]] = []
    for pt in weight_pts:
        w = pt.get("weight", {})
        grams = w.get("weightGrams")
        if grams is not None:
            kg = float(grams) / 1000.0
            ts = w.get("sampleTime", {}).get("physicalTime") or ""
            weights.append(
                {
                    "date": ts[:10] if len(ts) >= 10 else "unknown",
                    "timestamp": ts,
                    "weight_lbs": round(kg * 2.20462262, 2),
                    "weight_kg": round(kg, 2),
                }
            )
    weights.sort(key=lambda x: x["timestamp"])

    body_fat: list[dict[str, Any]] = []
    for pt in bf_pts:
        bf = pt.get("bodyFat", {})
        pct = bf.get("percentage") or bf.get("bodyFatPercentage")
        ts = bf.get("sampleTime", {}).get("physicalTime") or ""
        if pct is not None:
            body_fat.append(
                {
                    "date": ts[:10] if len(ts) >= 10 else "unknown",
                    "timestamp": ts,
                    "body_fat_pct": round(float(pct), 2),
                }
            )
    body_fat.sort(key=lambda x: x["timestamp"])

    change_lbs = (
        round(weights[-1]["weight_lbs"] - weights[0]["weight_lbs"], 2)
        if len(weights) >= 2
        else None
    )
    latest_weight_kg = weights[-1]["weight_kg"] if weights else None
    goals, _ = await _load_user_goals()
    computed_targets = _compute_goal_targets(goals, latest_weight_kg=latest_weight_kg)
    return {
        "user_profile": _build_user_profile(latest_weight_kg=latest_weight_kg),
        "goals": _compact_goals_summary(goals, computed_targets),
        "start_date": start,
        "end_date": end,
        "latest_weight_lbs": weights[-1]["weight_lbs"] if weights else None,
        "latest_weight_kg": latest_weight_kg,
        "weight_change_lbs": change_lbs,
        "weight_count": len(weights),
        "weights": weights,
        "body_fat_count": len(body_fat),
        "body_fat": body_fat,
    }


@mcp.tool(annotations=READ_ONLY_ANNOTATIONS)
async def get_user_profile() -> dict[str, Any]:
    """
    Get the user's base physiological profile (sex, height, birth year, age,
    estimated max HR, timezone), active mutable goals (North Star + Phase Milestone),
    and computed physiological targets (athletic recomp band, WHtR target, pace, protein floor).
    """
    _get_verified_token()
    goals, source = await _load_user_goals()
    computed = _compute_goal_targets(goals)
    return {
        "physiology": _build_user_profile(),
        "goals": goals,
        "goals_source": source,
        "computed_targets": computed,
    }


@mcp.tool(annotations=WRITE_ANNOTATIONS)
async def update_user_goals(
    goal_objective: str | None = None,
    target_weight_mode: str | None = None,
    custom_target_weight_lbs: float | None = None,
    pace_mode: str | None = None,
    target_date: str | None = None,
    clear_target_date: bool = False,
    milestone_phase: int | None = None,
    milestone_target_lbs: float | None = None,
    milestone_target_waist_in: float | None = None,
    milestone_approved: bool | None = None,
    notes: str | None = None,
    clear_notes: bool = False,
) -> dict[str, Any]:
    """
    Update the user's editable fitness goals in Firestore (shared with the local dashboard).
    IMPORTANT: ONLY call this tool when the user EXPLICITLY asks to change, set, or approve
    their goal, target weight, pace, target date, or Phase milestone. NEVER auto-rewrite goals
    silently during routine check-ins or coaching advice.
    """
    global _goals_cache, _goals_cache_ts
    _get_verified_token()

    before, _ = await _load_user_goals(force_refresh=True)
    after = dict(before)

    if goal_objective is not None:
        cleaned = goal_objective.strip()
        if not cleaned or len(cleaned) > 300:
            raise ValueError("goal_objective must be 1..300 characters.")
        after["goal_objective"] = cleaned

    if target_weight_mode is not None:
        wm = target_weight_mode.strip().lower()
        if wm not in VALID_WEIGHT_MODES:
            raise ValueError(f"target_weight_mode must be one of {VALID_WEIGHT_MODES}.")
        after["target_weight_mode"] = wm
        if wm == "optimal" and custom_target_weight_lbs is None:
            after["custom_target_weight_lbs"] = None

    if custom_target_weight_lbs is not None:
        val = float(custom_target_weight_lbs)
        if not (70.0 <= val <= 500.0):
            raise ValueError("custom_target_weight_lbs must be between 70 and 500.")
        after["custom_target_weight_lbs"] = round(val, 1)
        if target_weight_mode is None:
            after["target_weight_mode"] = "custom"

    if after["target_weight_mode"] == "custom" and not after.get("custom_target_weight_lbs"):
        raise ValueError("custom_target_weight_lbs is required when target_weight_mode is 'custom'.")

    if pace_mode is not None:
        pm = pace_mode.strip().lower()
        if pm not in VALID_PACE_MODES:
            raise ValueError(f"pace_mode must be one of {VALID_PACE_MODES}.")
        after["pace_mode"] = pm

    if clear_target_date:
        after["target_date"] = None
    elif target_date is not None:
        td = target_date.strip()
        parsed_dt = _parse_date(td).date()
        if parsed_dt <= datetime.now(USER_TZ).date():
            raise ValueError("target_date must be a future date (YYYY-MM-DD).")
        after["target_date"] = parsed_dt.isoformat()

    if after["pace_mode"] == "by_date" and not after.get("target_date"):
        raise ValueError("target_date (future YYYY-MM-DD) is required when pace_mode is 'by_date'.")

    if milestone_phase is not None:
        mp = int(milestone_phase)
        if not (1 <= mp <= 10):
            raise ValueError("milestone_phase must be between 1 and 10.")
        after["milestone_phase"] = mp

    if milestone_target_lbs is not None:
        ml = float(milestone_target_lbs)
        if not (70.0 <= ml <= 500.0):
            raise ValueError("milestone_target_lbs must be between 70 and 500.")
        after["milestone_target_lbs"] = round(ml, 1)

    if milestone_target_waist_in is not None:
        mw = float(milestone_target_waist_in)
        if not (20.0 <= mw <= 70.0):
            raise ValueError("milestone_target_waist_in must be between 20 and 70.")
        after["milestone_target_waist_in"] = round(mw, 1)

    if milestone_approved is not None:
        after["milestone_approved"] = bool(milestone_approved)

    if clear_notes:
        after["notes"] = ""
    elif notes is not None:
        cleaned_notes = notes.strip()
        if len(cleaned_notes) > 500:
            raise ValueError("notes must be at most 500 characters.")
        after["notes"] = cleaned_notes

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    after["updated_at"] = now_iso
    after["updated_by"] = "gemini_mcp"

    changed_fields = [
        k for k in after
        if k not in ("updated_at", "updated_by") and before.get(k) != after.get(k)
    ]

    db = _get_firestore_client()
    doc_ref = db.collection(PROFILE_COLLECTION).document("goals")
    await doc_ref.set(after, merge=True)
    if changed_fields:
        await doc_ref.collection("history").add(
            {
                "changed_fields": changed_fields,
                "before": before,
                "after": after,
                "updated_at": now_iso,
                "updated_by": "gemini_mcp",
            }
        )

    _goals_cache = {**after, "_source": "firestore"}
    _goals_cache_ts = time.time()

    return {
        "ok": True,
        "changed_fields": changed_fields,
        "before": before,
        "after": after,
        "computed_targets": _compute_goal_targets(after),
    }


@mcp.tool(annotations=READ_ONLY_ANNOTATIONS)
async def get_daily_cut_summary(
    days: int = 7,
) -> dict[str, Any]:
    """
    One-stop daily summary combining TDEE (total calories burned), nutrition intake & macros,
    exact net caloric deficit, hydration, weight, and recovery vitals (RHR, resp rate, SpO2, HRV).
    Defaults to the last 7 days (max 14).
    """
    clamped_days = max(1, min(int(days), 14))
    start, end = _default_date_range(None, None, default_days=clamped_days)

    energy_fn = getattr(get_daily_energy, "fn", get_daily_energy)
    meals_fn = getattr(get_meals, "fn", get_meals)
    hydration_fn = getattr(get_hydration, "fn", get_hydration)
    body_fn = getattr(get_body_composition, "fn", get_body_composition)
    recovery_fn = getattr(get_recovery_vitals, "fn", get_recovery_vitals)
    checkins_fn = getattr(get_daily_checkins, "fn", get_daily_checkins)

    async def _safe_checkins() -> dict[str, Any]:
        try:
            return await checkins_fn(start_date=start, end_date=end)
        except Exception:
            return {"checkins": []}

    energy_res, meals_res, hydration_res, body_res, recovery_res, checkins_res = (
        await asyncio.gather(
            energy_fn(start_date=start, end_date=end),
            meals_fn(start_date=start, end_date=end),
            hydration_fn(start_date=start, end_date=end),
            body_fn(start_date=start, end_date=end),
            recovery_fn(start_date=start, end_date=end),
            _safe_checkins(),
        )
    )

    by_day: dict[str, dict[str, Any]] = defaultdict(dict)

    for day, e in energy_res.get("daily_energy", {}).items():
        by_day[day]["tdee_kcal"] = e.get("tdee_kcal", 0.0)
        by_day[day]["active_zone_minutes"] = e.get("active_zone_minutes", 0)

    # Aggregate meals per day with exact-duplicate filtering
    meal_agg: dict[str, dict[str, float]] = defaultdict(
        lambda: {"kcal": 0.0, "protein_g": 0.0, "carbs_g": 0.0, "fat_g": 0.0, "count": 0}
    )
    seen_meals: set[tuple[str, str, int, str]] = set()
    duplicate_meals_filtered = 0
    for pt in meals_res.get("meals", []):
        nl = pt.get("nutritionLog", {})
        interval = nl.get("interval", {})
        day = _format_proto_date(
            interval.get("civilStartTime", {}).get("date") or interval.get("startTime")
        )
        food_key = str(nl.get("foodDisplayName") or nl.get("food") or "").strip().lower()
        kcal_val = float(nl.get("energy", {}).get("kcal") or 0)
        start_min = str(interval.get("startTime") or "")[:16]
        sig = (day, food_key, round(kcal_val), start_min)
        if food_key and sig in seen_meals:
            duplicate_meals_filtered += 1
            continue
        seen_meals.add(sig)

        meal_agg[day]["kcal"] += kcal_val
        meal_agg[day]["carbs_g"] += float(nl.get("totalCarbohydrate", {}).get("grams") or 0)
        meal_agg[day]["fat_g"] += float(nl.get("totalFat", {}).get("grams") or 0)
        for n in nl.get("nutrients", []):
            if str(n.get("nutrient", "")).upper() == "PROTEIN":
                meal_agg[day]["protein_g"] += float(n.get("quantity", {}).get("grams") or 0)
        meal_agg[day]["count"] += 1

    for day, m in meal_agg.items():
        by_day[day]["intake_kcal"] = round(m["kcal"], 1)
        by_day[day]["protein_g"] = round(m["protein_g"], 1)
        by_day[day]["carbs_g"] = round(m["carbs_g"], 1)
        by_day[day]["fat_g"] = round(m["fat_g"], 1)
        by_day[day]["meal_count"] = int(m["count"])

    for day, h in hydration_res.get("daily_totals", {}).items():
        by_day[day]["water_ml"] = h["milliliters"]
        by_day[day]["water_fl_oz"] = h["fl_oz"]

    for w in body_res.get("weights", []):
        by_day[w["date"]]["weight_lbs"] = w["weight_lbs"]

    for day, v in recovery_res.get("daily_vitals", {}).items():
        by_day[day].update(v)

    latest_waist_in: float | None = None
    for c in checkins_res.get("checkins", []):
        c_day = str(c.get("date") or "")
        if c_day:
            checkin_summary = {
                k: v
                for k, v in c.items()
                if k in ("soreness", "muscle_soreness", "cramp_warning", "energy_level", "waist_in", "waist_cm", "notes")
            }
            if checkin_summary:
                by_day[c_day]["checkin"] = checkin_summary
        if latest_waist_in is None and c.get("waist_in") is not None:
            latest_waist_in = float(c["waist_in"])

    for day, d in by_day.items():
        if "tdee_kcal" in d and "intake_kcal" in d:
            d["net_deficit_kcal"] = round(d["tdee_kcal"] - d["intake_kcal"], 1)

    goals, _ = await _load_user_goals()
    computed_targets = _compute_goal_targets(
        goals,
        latest_weight_kg=body_res.get("latest_weight_kg"),
        latest_waist_in=latest_waist_in,
    )
    return {
        "timezone": USER_TIMEZONE_NAME,
        "user_profile": _build_user_profile(
            latest_weight_kg=body_res.get("latest_weight_kg"),
            latest_waist_in=latest_waist_in,
        ),
        "goals": _compact_goals_summary(goals, computed_targets),
        "start_date": start,
        "end_date": end,
        "latest_weight_lbs": body_res.get("latest_weight_lbs"),
        "latest_waist_in": latest_waist_in,
        "duplicate_meals_filtered": duplicate_meals_filtered,
        "daily_summary": dict(sorted(by_day.items())),
    }


@mcp.tool(annotations=WRITE_ANNOTATIONS)
async def log_strength_sets(
    exercise: str,
    sets: int | list[dict[str, Any]],
    reps: int | None = None,
    weight_lbs: float | None = None,
    weight_kg: float | None = None,
    rpe: float | None = None,
    notes: str | None = None,
    logged_at: str | None = None,
) -> dict[str, Any]:
    """
    Log strength-training sets (exercise, reps, weight, RPE) to Firestore (`strength_logs`).

    Supports two styles:
    - Straight sets: sets=3, reps=10, weight_lbs=135, rpe=8
    - Variable/pyramid sets: sets=[{"reps": 10, "weight_lbs": 135}, {"reps": 8, "weight_lbs": 145, "rpe": 9}]
    """
    _get_verified_token()

    exercise_clean = exercise.strip()
    if not exercise_clean:
        raise ValueError("exercise name is required.")

    normalized_sets: list[dict[str, Any]] = []
    if isinstance(sets, int):
        if sets < 1 or sets > 30:
            raise ValueError("sets count must be between 1 and 30.")
        if reps is None or reps < 1:
            raise ValueError("reps must be provided when sets is an integer.")
        w_lbs = (
            round(float(weight_lbs), 2)
            if weight_lbs is not None
            else (round(float(weight_kg) * 2.20462262, 2) if weight_kg is not None else 0.0)
        )
        for _ in range(sets):
            entry: dict[str, Any] = {"reps": int(reps), "weight_lbs": w_lbs}
            if rpe is not None:
                entry["rpe"] = round(float(rpe), 1)
            normalized_sets.append(entry)
    elif isinstance(sets, list) and len(sets) > 0:
        for item in sets:
            r = int(item.get("reps") or reps or 0)
            if r < 1:
                raise ValueError("Each set must include a positive 'reps' count.")
            if item.get("weight_lbs") is not None:
                w_lbs = round(float(item["weight_lbs"]), 2)
            elif item.get("weight_kg") is not None:
                w_lbs = round(float(item["weight_kg"]) * 2.20462262, 2)
            elif weight_lbs is not None:
                w_lbs = round(float(weight_lbs), 2)
            elif weight_kg is not None:
                w_lbs = round(float(weight_kg) * 2.20462262, 2)
            else:
                w_lbs = 0.0
            entry = {"reps": r, "weight_lbs": w_lbs}
            set_rpe = item.get("rpe", rpe)
            if set_rpe is not None:
                entry["rpe"] = round(float(set_rpe), 1)
            normalized_sets.append(entry)
    else:
        raise ValueError("sets must be a positive integer or a non-empty list of set objects.")

    if logged_at:
        dt = datetime.fromisoformat(logged_at.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt = dt.astimezone(timezone.utc)
    else:
        dt = datetime.now(timezone.utc)

    total_reps = sum(s["reps"] for s in normalized_sets)
    total_volume = round(sum(s["reps"] * s["weight_lbs"] for s in normalized_sets), 1)
    top_weight = max((s["weight_lbs"] for s in normalized_sets), default=0.0)

    doc: dict[str, Any] = {
        "date": dt.date().isoformat(),
        "logged_at": dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "exercise": exercise_clean,
        "exercise_key": exercise_clean.lower(),
        "sets": normalized_sets,
        "total_sets": len(normalized_sets),
        "total_reps": total_reps,
        "total_volume_lbs": total_volume,
        "top_weight_lbs": top_weight,
    }
    if notes:
        doc["notes"] = notes.strip()

    db = _get_firestore_client()
    _, doc_ref = await db.collection(STRENGTH_COLLECTION).add(doc)
    return {
        "status": "logged",
        "log_id": doc_ref.id,
        "entry": doc,
    }


@mcp.tool(annotations=READ_ONLY_ANNOTATIONS)
async def get_strength_logs(
    start_date: str | None = None,
    end_date: str | None = None,
    exercise: str | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    """
    Read logged strength-training sets from Firestore (`strength_logs`).
    Defaults to the last 14 days. Optionally filter by exercise substring (case-insensitive).
    """
    _get_verified_token()
    start, end = _default_date_range(start_date, end_date, default_days=14)
    clamped_limit = max(1, min(int(limit), 200))

    db = _get_firestore_client()
    query = (
        db.collection(STRENGTH_COLLECTION)
        .where("date", ">=", start)
        .where("date", "<=", end)
    )

    entries: list[dict[str, Any]] = []
    exercise_filter = exercise.strip().lower() if exercise else None
    async for snap in query.stream():
        data = snap.to_dict() or {}
        if exercise_filter and exercise_filter not in str(data.get("exercise_key", "")):
            continue
        entries.append({"log_id": snap.id, **data})

    entries.sort(key=lambda x: str(x.get("logged_at", "")), reverse=True)
    entries = entries[:clamped_limit]

    by_exercise: dict[str, dict[str, Any]] = {}
    for e in entries:
        name = str(e.get("exercise", "Unknown"))
        agg = by_exercise.setdefault(
            name,
            {"sessions": 0, "total_sets": 0, "total_volume_lbs": 0.0, "top_weight_lbs": 0.0},
        )
        agg["sessions"] += 1
        agg["total_sets"] += int(e.get("total_sets") or 0)
        agg["total_volume_lbs"] = round(
            agg["total_volume_lbs"] + float(e.get("total_volume_lbs") or 0), 1
        )
        agg["top_weight_lbs"] = max(agg["top_weight_lbs"], float(e.get("top_weight_lbs") or 0))

    return {
        "start_date": start,
        "end_date": end,
        "log_count": len(entries),
        "exercise_summary": by_exercise,
        "logs": entries,
    }


@mcp.tool(annotations=DELETE_ANNOTATIONS)
async def delete_strength_log(log_id: str) -> dict[str, Any]:
    """
    Delete a previously logged strength-training entry from Firestore by its `log_id`.
    """
    _get_verified_token()
    cleaned_id = log_id.strip()
    if not cleaned_id:
        raise ValueError("log_id is required.")

    db = _get_firestore_client()
    doc_ref = db.collection(STRENGTH_COLLECTION).document(cleaned_id)
    snap = await doc_ref.get()
    if not snap.exists:
        return {"status": "not_found", "log_id": cleaned_id}
    await doc_ref.delete()
    return {"status": "deleted", "log_id": cleaned_id}


@mcp.tool(annotations=WRITE_ANNOTATIONS)
async def log_mindfulness_session(
    duration_minutes: float,
    session_type: str = "MEDITATION",
    calm_pct: float | None = None,
    stillness_pct: float | None = None,
    avg_hr_bpm: float | None = None,
    recoveries: int | None = None,
    source: str = "Muse",
    notes: str | None = None,
    logged_at: str | None = None,
) -> dict[str, Any]:
    """
    Log a mindfulness or meditation session (e.g., Muse S Athena, breathing, guided)
    into Firestore (`mindfulness_logs`).

    Args:
        duration_minutes: Session length in minutes (e.g., 15).
        session_type: MEDITATION, BREATHING, GUIDED, UNGUIDED, FOCUS, SLEEP_PREP, or OTHER.
        calm_pct: Optional Calm percentage (0-100).
        stillness_pct: Optional Stillness / body-stillness percentage (0-100).
        avg_hr_bpm: Optional average heart rate during the session (bpm).
        recoveries: Optional count of focus/calm recoveries.
        source: Device or app name (e.g., "Muse S Athena", "Health Coach").
        notes: Optional session notes.
        logged_at: Optional ISO-8601 UTC timestamp. Defaults to now.
    """
    _get_verified_token()
    if duration_minutes <= 0 or duration_minutes > 480:
        raise ValueError("duration_minutes must be between 0 and 480.")

    if logged_at:
        dt = datetime.fromisoformat(logged_at.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt = dt.astimezone(timezone.utc)
    else:
        dt = datetime.now(timezone.utc)

    doc: dict[str, Any] = {
        "date": dt.date().isoformat(),
        "logged_at": dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "duration_minutes": round(float(duration_minutes), 1),
        "session_type": session_type.strip().upper() or "MEDITATION",
        "source": source.strip() or "Mindfulness",
    }
    if calm_pct is not None:
        doc["calm_pct"] = round(float(calm_pct), 1)
    if stillness_pct is not None:
        doc["stillness_pct"] = round(float(stillness_pct), 1)
    if avg_hr_bpm is not None:
        doc["avg_hr_bpm"] = round(float(avg_hr_bpm), 1)
    if recoveries is not None:
        doc["recoveries"] = int(recoveries)
    if notes:
        doc["notes"] = notes.strip()

    db = _get_firestore_client()
    _, doc_ref = await db.collection(MINDFULNESS_COLLECTION).add(doc)
    return {
        "status": "logged",
        "log_id": doc_ref.id,
        "session": doc,
    }


@mcp.tool(annotations=READ_ONLY_ANNOTATIONS)
async def get_mindfulness_logs(
    start_date: str | None = None,
    end_date: str | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    """
    Read logged mindfulness / meditation sessions from Firestore (`mindfulness_logs`).
    Defaults to the last 14 days.
    """
    _get_verified_token()
    start, end = _default_date_range(start_date, end_date, default_days=14)
    clamped_limit = max(1, min(int(limit), 200))

    db = _get_firestore_client()
    query = (
        db.collection(MINDFULNESS_COLLECTION)
        .where("date", ">=", start)
        .where("date", "<=", end)
    )

    sessions: list[dict[str, Any]] = []
    async for snap in query.stream():
        data = snap.to_dict() or {}
        sessions.append({"log_id": snap.id, **data})

    sessions.sort(key=lambda x: str(x.get("logged_at", "")), reverse=True)
    sessions = sessions[:clamped_limit]

    total_mins = round(sum(float(s.get("duration_minutes") or 0) for s in sessions), 1)
    calm_vals = [float(s["calm_pct"]) for s in sessions if s.get("calm_pct") is not None]
    still_vals = [
        float(s["stillness_pct"]) for s in sessions if s.get("stillness_pct") is not None
    ]

    return {
        "start_date": start,
        "end_date": end,
        "session_count": len(sessions),
        "total_minutes": total_mins,
        "avg_calm_pct": round(sum(calm_vals) / len(calm_vals), 1) if calm_vals else None,
        "avg_stillness_pct": (
            round(sum(still_vals) / len(still_vals), 1) if still_vals else None
        ),
        "sessions": sessions,
    }


@mcp.tool(annotations=DELETE_ANNOTATIONS)
async def delete_mindfulness_log(log_id: str) -> dict[str, Any]:
    """
    Delete a logged mindfulness session from Firestore by its `log_id`.
    """
    _get_verified_token()
    cleaned_id = log_id.strip()
    if not cleaned_id:
        raise ValueError("log_id is required.")

    db = _get_firestore_client()
    doc_ref = db.collection(MINDFULNESS_COLLECTION).document(cleaned_id)
    snap = await doc_ref.get()
    if not snap.exists:
        return {"status": "not_found", "log_id": cleaned_id}
    await doc_ref.delete()
    return {"status": "deleted", "log_id": cleaned_id}


async def _batch_delete_data_points(
    data_type: str,
    names: list[str],
) -> dict[str, Any]:
    """Delete one or more Google Health API v4 dataPoints via :batchDelete."""
    token = _get_verified_token()
    cleaned = [n.strip() for n in names if isinstance(n, str) and n.strip()]
    if not cleaned:
        raise ValueError("At least one non-empty dataPoint resource name is required.")

    url = f"{HEALTH_API_BASE}/users/me/dataTypes/{data_type}/dataPoints:batchDelete"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(url, headers=headers, json={"names": cleaned})
        if resp.status_code == 401:
            raise PermissionError(
                "Google Health API rejected the token (401). Please re-authenticate."
            )
        if resp.status_code == 403:
            raise PermissionError(
                f"Google Health API returned 403 Forbidden deleting '{data_type}'."
            )
        if resp.status_code >= 400:
            raise ValueError(
                f"Google Health API returned {resp.status_code} deleting '{data_type}': {resp.text}"
            )
        return {"status": "deleted", "deleted_count": len(cleaned), "names": cleaned}


@mcp.tool(annotations=DELETE_ANNOTATIONS)
async def delete_meals(data_point_names: list[str]) -> dict[str, Any]:
    """
    Delete one or more duplicate/mistyped meal entries from Google Health (`nutrition-log`).
    Pass the `name` field(s) returned by `get_meals` (e.g., ["users/.../dataTypes/nutrition-log/dataPoints/..."]).
    """
    return await _batch_delete_data_points("nutrition-log", data_point_names)


@mcp.tool(annotations=DELETE_ANNOTATIONS)
async def delete_hydration_logs(data_point_names: list[str]) -> dict[str, Any]:
    """
    Delete one or more duplicate/mistyped water entries from Google Health (`hydration-log`).
    Pass the `name` field(s) returned by `get_hydration`.
    """
    return await _batch_delete_data_points("hydration-log", data_point_names)


@mcp.tool(annotations=WRITE_ANNOTATIONS)
async def log_daily_checkin(
    date: str | None = None,
    soreness: float | None = None,
    muscle_soreness: dict[str, float] | None = None,
    cramp_warning: bool | None = None,
    energy_level: float | None = None,
    waist_in: float | None = None,
    waist_cm: float | None = None,
    notes: str | None = None,
) -> dict[str, Any]:
    """
    Log or update a daily readiness check-in & body measurement in Firestore (`daily_checkins`).
    Upserts into one document per date (YYYY-MM-DD, defaults to local today) without overwriting
    other fields already logged for that day.

    Args:
        date: Optional YYYY-MM-DD date (defaults to today in USER_TIMEZONE).
        soreness: Optional overall soreness score (0-10).
        muscle_soreness: Optional per-muscle scores, e.g. {"hamstrings": 3, "quads": 2}.
        cramp_warning: Optional boolean flag indicating cramp tightness/warning.
        energy_level: Optional subjective energy score (0-10).
        waist_in: Optional waist circumference in inches.
        waist_cm: Optional waist circumference in centimeters.
        notes: Optional short note.
    """
    _get_verified_token()
    day = _parse_date(date).date().isoformat() if date else datetime.now(USER_TZ).date().isoformat()

    doc: dict[str, Any] = {
        "date": day,
        "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if soreness is not None:
        doc["soreness"] = round(float(soreness), 1)
    if muscle_soreness:
        doc["muscle_soreness"] = {
            str(k).strip().lower(): round(float(v), 1) for k, v in muscle_soreness.items()
        }
    if cramp_warning is not None:
        doc["cramp_warning"] = bool(cramp_warning)
    if energy_level is not None:
        doc["energy_level"] = round(float(energy_level), 1)
    if waist_in is not None:
        doc["waist_in"] = round(float(waist_in), 2)
        doc["waist_cm"] = round(float(waist_in) * 2.54, 1)
    elif waist_cm is not None:
        doc["waist_cm"] = round(float(waist_cm), 1)
        doc["waist_in"] = round(float(waist_cm) / 2.54, 2)
    if notes is not None:
        doc["notes"] = notes.strip()

    db = _get_firestore_client()
    doc_ref = db.collection(CHECKIN_COLLECTION).document(day)
    await doc_ref.set(doc, merge=True)
    snap = await doc_ref.get()
    return {
        "status": "logged",
        "date": day,
        "checkin": snap.to_dict() or doc,
    }


@mcp.tool(annotations=READ_ONLY_ANNOTATIONS)
async def get_daily_checkins(
    start_date: str | None = None,
    end_date: str | None = None,
    limit: int = 30,
) -> dict[str, Any]:
    """
    Read daily readiness check-ins (soreness, cramp warnings, energy, waist circumference)
    from Firestore (`daily_checkins`). Defaults to the last 30 days.
    """
    _get_verified_token()
    start, end = _default_date_range(start_date, end_date, default_days=30)
    clamped_limit = max(1, min(int(limit), 100))

    db = _get_firestore_client()
    query = (
        db.collection(CHECKIN_COLLECTION)
        .where("date", ">=", start)
        .where("date", "<=", end)
    )

    items: list[dict[str, Any]] = []
    async for snap in query.stream():
        data = snap.to_dict() or {}
        if "date" not in data:
            data["date"] = snap.id
        items.append(data)

    items.sort(key=lambda x: str(x.get("date", "")), reverse=True)
    items = items[:clamped_limit]

    waist_entries = [i for i in items if i.get("waist_in") is not None]
    return {
        "timezone": USER_TIMEZONE_NAME,
        "start_date": start,
        "end_date": end,
        "checkin_count": len(items),
        "latest_waist_in": waist_entries[0]["waist_in"] if waist_entries else None,
        "checkins": items,
    }


@mcp.tool(annotations=READ_ONLY_ANNOTATIONS)
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

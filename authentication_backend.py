# authentication_backend.py

import base64
import hashlib
import hmac
import html
import os
import re
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import psycopg
import resend
from dotenv import load_dotenv
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from auth_database import (
    create_session,
    create_user,
    delete_expired_sessions,
    delete_session,
    get_session_by_token,
    get_user_by_email,
    set_user_status,
)


# ============================================================================
# ENVIRONMENT
# ============================================================================

load_dotenv(".env.local")


def _required_env(name: str) -> str:
    value = os.getenv(name)

    if not value:
        raise RuntimeError(
            f"Required environment variable is missing: {name}"
        )

    return value.strip()


RESEND_API_KEY = _required_env("RESEND_API_KEY")
ADMIN_EMAIL = _required_env("ADMIN_EMAIL")
APP_BASE_URL = _required_env("APP_BASE_URL").rstrip("/")
RESEND_FROM_EMAIL = _required_env("RESEND_FROM_EMAIL")
APPROVAL_TOKEN_SECRET = _required_env(
    "APPROVAL_TOKEN_SECRET"
)

resend.api_key = RESEND_API_KEY


# ============================================================================
# ROUTER
# ============================================================================

router = APIRouter(
    tags=["authentication"],
)


# ============================================================================
# CONFIGURATION
# ============================================================================

SESSION_COOKIE_NAME = os.getenv(
    "SESSION_COOKIE_NAME",
    "tradingbot_session",
)

SESSION_DAYS = int(
    os.getenv(
        "SESSION_DAYS",
        "7",
    )
)

AUTH_COOKIE_SECURE = (
    os.getenv(
        "AUTH_COOKIE_SECURE",
        "false",
    )
    .strip()
    .lower()
    in {
        "1",
        "true",
        "yes",
        "on",
    }
)

PASSWORD_MIN_LENGTH = 8

APPROVAL_TOKEN_HOURS = int(
    os.getenv(
        "APPROVAL_TOKEN_HOURS",
        "48",
    )
)


# ============================================================================
# REQUEST MODELS
# ============================================================================


class RegisterRequest(BaseModel):
    name: str
    surname: str
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


# ============================================================================
# PASSWORD HASHING
# ============================================================================


def hash_password(password: str) -> str:
    password_bytes = password.encode("utf-8")

    salt = secrets.token_bytes(16)

    derived_key = hashlib.scrypt(
        password_bytes,
        salt=salt,
        n=16384,
        r=8,
        p=1,
        dklen=64,
    )

    return (
        "scrypt$"
        f"{salt.hex()}$"
        f"{derived_key.hex()}"
    )


def verify_password(
    password: str,
    stored_hash: str,
) -> bool:

    try:
        algorithm, salt_hex, key_hex = (
            stored_hash.split("$", 2)
        )

        if algorithm != "scrypt":
            return False

        salt = bytes.fromhex(salt_hex)
        expected_key = bytes.fromhex(key_hex)

        derived_key = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=16384,
            r=8,
            p=1,
            dklen=len(expected_key),
        )

        return hmac.compare_digest(
            derived_key,
            expected_key,
        )

    except (
        ValueError,
        TypeError,
    ):
        return False


# ============================================================================
# VALIDATION
# ============================================================================


def normalize_email(email: str) -> str:
    return str(email).strip().lower()


def validate_email(email: str) -> bool:
    return (
        re.fullmatch(
            r"[^@\s]+@[^@\s]+\.[^@\s]+",
            email,
        )
        is not None
    )


def validate_password(password: str) -> None:
    if len(password) < PASSWORD_MIN_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Password must contain at least "
                f"{PASSWORD_MIN_LENGTH} characters."
            ),
        )


def sanitize_user(
    user: Dict[str, Any],
) -> Dict[str, Any]:

    return {
        "id": str(user["id"]),
        "name": user["name"],
        "surname": user["surname"],
        "email": user["email"],
        "status": user["status"],
        "created_at": user["created_at"],
        "approved_at": user["approved_at"],
    }


# ============================================================================
# APPROVAL TOKEN
# ============================================================================
#
# Token contains:
#   action
#   user_id
#   timestamp
#
# Token is signed with APPROVAL_TOKEN_SECRET.
#
# APPROVE/REJECT only works while the account is still "pending".
# Therefore once one action is executed, the opposite action cannot later
# change the account.
# ============================================================================


def _sign_approval_payload(
    payload: str,
) -> str:

    signature = hmac.new(
        APPROVAL_TOKEN_SECRET.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).digest()

    return base64.urlsafe_b64encode(
        signature
    ).decode("ascii").rstrip("=")


def create_approval_token(
    action: str,
    user_id: str,
) -> str:

    if action not in {
        "approve",
        "reject",
    }:
        raise ValueError("Invalid approval action.")

    timestamp = int(time.time())

    payload = (
        f"{action}|"
        f"{user_id}|"
        f"{timestamp}"
    )

    payload_encoded = base64.urlsafe_b64encode(
        payload.encode("utf-8")
    ).decode("ascii").rstrip("=")

    signature = _sign_approval_payload(
        payload_encoded
    )

    return (
        f"{payload_encoded}."
        f"{signature}"
    )


def verify_approval_token(
    token: str,
) -> Optional[Dict[str, Any]]:

    try:
        payload_encoded, signature = token.split(
            ".",
            1,
        )

        expected_signature = _sign_approval_payload(
            payload_encoded
        )

        if not hmac.compare_digest(
            signature,
            expected_signature,
        ):
            return None

        padding = "=" * (
            (-len(payload_encoded)) % 4
        )

        payload = base64.urlsafe_b64decode(
            payload_encoded + padding
        ).decode("utf-8")

        action, user_id, timestamp_raw = (
            payload.split("|", 2)
        )

        timestamp = int(timestamp_raw)

        now = int(time.time())

        max_age = (
            APPROVAL_TOKEN_HOURS * 60 * 60
        )

        if timestamp > now:
            return None

        if now - timestamp > max_age:
            return None

        if action not in {
            "approve",
            "reject",
        }:
            return None

        if not user_id:
            return None

        return {
            "action": action,
            "user_id": user_id,
            "timestamp": timestamp,
        }

    except (
        ValueError,
        TypeError,
        UnicodeDecodeError,
        base64.binascii.Error,
    ):
        return None


# ============================================================================
# RESEND EMAIL
# ============================================================================


def send_admin_approval_email(
    user: Dict[str, Any],
) -> None:

    user_id = str(user["id"])

    approve_token = create_approval_token(
        "approve",
        user_id,
    )

    reject_token = create_approval_token(
        "reject",
        user_id,
    )

    approve_url = (
        f"{APP_BASE_URL}"
        f"/api/admin/approve/"
        f"{approve_token}"
    )

    reject_url = (
        f"{APP_BASE_URL}"
        f"/api/admin/reject/"
        f"{reject_token}"
    )

    name = html.escape(
        str(user["name"])
    )

    surname = html.escape(
        str(user["surname"])
    )

    email = html.escape(
        str(user["email"])
    )

    html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>New user registration</title>
</head>

<body
    style="
        font-family: Arial, sans-serif;
        background: #f4f4f4;
        padding: 30px;
    "
>

    <div
        style="
            max-width: 620px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
        "
    >

        <h2>New User Registration</h2>

        <p>A new user has registered on RoyaleTrades.</p>

        <p>
            <strong>Name:</strong>
            {name} {surname}
        </p>

        <p>
            <strong>Email:</strong>
            {email}
        </p>

        <div style="margin-top: 30px;">

            <a
                href="{approve_url}"
                style="
                    display: inline-block;
                    padding: 12px 22px;
                    background: #16a34a;
                    color: white;
                    text-decoration: none;
                    border-radius: 6px;
                    margin-right: 10px;
                "
            >
                APPROVE
            </a>

            <a
                href="{reject_url}"
                style="
                    display: inline-block;
                    padding: 12px 22px;
                    background: #dc2626;
                    color: white;
                    text-decoration: none;
                    border-radius: 6px;
                "
            >
                REJECT
            </a>

        </div>

        <p
            style="
                margin-top: 30px;
                color: #666;
                font-size: 13px;
            "
        >
            These approval links expire after
            {APPROVAL_TOKEN_HOURS} hours.
        </p>

    </div>

</body>
</html>
"""

    resend.Emails.send(
        {
            "from": RESEND_FROM_EMAIL,
            "to": [ADMIN_EMAIL],
            "subject": "New RoyaleTrades user registration",
            "html": html_body,
        }
    )


# ============================================================================
# SESSION HELPERS
# ============================================================================


def create_login_session(
    user_id: str,
) -> tuple[str, datetime]:

    token = secrets.token_urlsafe(48)

    expires_at = (
        datetime.now(timezone.utc)
        + timedelta(days=SESSION_DAYS)
    )

    create_session(
        user_id=user_id,
        token=token,
        expires_at=expires_at,
    )

    return token, expires_at


def get_current_session(
    request: Request,
) -> Optional[Dict[str, Any]]:

    token = request.cookies.get(
        SESSION_COOKIE_NAME
    )

    if not token:
        return None

    session = get_session_by_token(token)

    if session is None:
        return None

    expires_at = session["expires_at"]

    if expires_at is None:
        return None

    if expires_at <= datetime.now(timezone.utc):

        try:
            delete_session(token)

        except Exception:
            pass

        return None

    return session


def require_authenticated_user(
    request: Request,
) -> Dict[str, Any]:

    session = get_current_session(request)

    if session is None:
        raise HTTPException(
            status_code=401,
            detail="Authentication required.",
        )

    if session.get("status") != "approved":
        raise HTTPException(
            status_code=403,
            detail="Account is not approved.",
        )

    return session


def set_session_cookie(
    response: Response,
    token: str,
) -> None:

    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=AUTH_COOKIE_SECURE,
        samesite="lax",
        max_age=SESSION_DAYS * 24 * 60 * 60,
        path="/",
    )


def clear_session_cookie(
    response: Response,
) -> None:

    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
    )


# ============================================================================
# REGISTER
# ============================================================================


@router.post("/api/auth/register")
def register(
    payload: RegisterRequest,
) -> Dict[str, Any]:

    name = str(
        payload.name
    ).strip()

    surname = str(
        payload.surname
    ).strip()

    email = normalize_email(
        payload.email
    )

    password = payload.password

    if not name:
        raise HTTPException(
            status_code=400,
            detail="Name is required.",
        )

    if not surname:
        raise HTTPException(
            status_code=400,
            detail="Surname is required.",
        )

    if not validate_email(email):
        raise HTTPException(
            status_code=400,
            detail="Invalid email address.",
        )

    validate_password(password)

    existing_user = get_user_by_email(
        email
    )

    if existing_user is not None:
        raise HTTPException(
            status_code=409,
            detail=(
                "An account with this email "
                "already exists."
            ),
        )

    password_hash = hash_password(
        password
    )

    try:

        user = create_user(
            name=name,
            surname=surname,
            email=email,
            password_hash=password_hash,
        )

    except psycopg.errors.UniqueViolation:

        raise HTTPException(
            status_code=409,
            detail=(
                "An account with this email "
                "already exists."
            ),
        )

    # ---------------------------------------------------------
    # SEND ADMIN APPROVAL EMAIL
    # ---------------------------------------------------------

    try:

        send_admin_approval_email(
            user
        )

    except Exception as error:

        print(
            "RESEND APPROVAL EMAIL ERROR:",
            error,
        )

        return {
            "success": True,
            "status": user["status"],
            "email_sent": False,
            "message": (
                "Registration was created, "
                "but the approval email could not "
                "be sent."
            ),
        }

    return {
        "success": True,
        "status": user["status"],
        "email_sent": True,
        "message": (
            "Registration submitted. "
            "Your account is waiting for approval."
        ),
    }


# ============================================================================
# LOGIN
# ============================================================================


@router.post("/api/auth/login")
def login(
    payload: LoginRequest,
    response: Response,
) -> Dict[str, Any]:

    email = normalize_email(
        payload.email
    )

    password = payload.password

    user = get_user_by_email(
        email
    )

    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password.",
        )

    if not verify_password(
        password,
        user["password_hash"],
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password.",
        )

    status = user["status"]

    if status == "pending":

        raise HTTPException(
            status_code=403,
            detail=(
                "Your account is waiting "
                "for approval."
            ),
        )

    if status == "rejected":

        raise HTTPException(
            status_code=403,
            detail=(
                "Your account has been rejected."
            ),
        )

    if status != "approved":

        raise HTTPException(
            status_code=403,
            detail=(
                "Your account is not approved."
            ),
        )

    delete_expired_sessions()

    token, expires_at = (
        create_login_session(
            str(user["id"])
        )
    )

    set_session_cookie(
        response,
        token,
    )

    return {
        "success": True,
        "authenticated": True,
        "user": sanitize_user(user),
        "expires_at": expires_at,
    }


# ============================================================================
# CURRENT USER
# ============================================================================


@router.get("/api/auth/me")
def me(
    request: Request,
) -> Dict[str, Any]:

    session = get_current_session(
        request
    )

    if session is None:
        return {
            "authenticated": False,
        }

    if session.get("status") != "approved":
        return {
            "authenticated": False,
        }

    return {
        "authenticated": True,
        "user": {
            "id": str(
                session["user_id"]
            ),
            "name": session["name"],
            "surname": session["surname"],
            "email": session["email"],
            "status": session["status"],
        },
    }


# ============================================================================
# LOGOUT
# ============================================================================


@router.post("/api/auth/logout")
def logout(
    request: Request,
    response: Response,
) -> Dict[str, Any]:

    token = request.cookies.get(
        SESSION_COOKIE_NAME
    )

    if token:

        try:
            delete_session(
                token
            )

        except Exception as error:

            print(
                "Session deletion error:",
                error,
            )

    clear_session_cookie(
        response
    )

    return {
        "success": True,
        "authenticated": False,
    }


# ============================================================================
# ADMIN APPROVE
# ============================================================================


@router.get(
    "/api/admin/approve/{token}",
    response_class=HTMLResponse,
)
def approve_user(
    token: str,
) -> HTMLResponse:

    data = verify_approval_token(
        token
    )

    if data is None:
        return HTMLResponse(
            content="""
            <h2>Invalid or expired approval link.</h2>
            """,
            status_code=400,
        )

    if data["action"] != "approve":
        return HTMLResponse(
            content="""
            <h2>Invalid approval action.</h2>
            """,
            status_code=400,
        )

    user = get_user_by_email(
        "__not_used__"
    )

    # The user is loaded by ID below.
    from auth_database import get_user_by_id

    user = get_user_by_id(
        data["user_id"]
    )

    if user is None:
        return HTMLResponse(
            content="""
            <h2>User not found.</h2>
            """,
            status_code=404,
        )

    if user["status"] != "pending":
        status = html.escape(
            str(user["status"])
        )

        return HTMLResponse(
            content=f"""
            <h2>This account has already been processed.</h2>
            <p>Current status: <strong>{status}</strong></p>
            """,
            status_code=200,
        )

    updated_user = set_user_status(
        data["user_id"],
        "approved",
    )

    if updated_user is None:
        return HTMLResponse(
            content="""
            <h2>Could not approve the user.</h2>
            """,
            status_code=500,
        )

    return HTMLResponse(
        content="""
        <h2>Account approved.</h2>
        <p>The user can now log in.</p>
        """,
        status_code=200,
    )


# ============================================================================
# ADMIN REJECT
# ============================================================================


@router.get(
    "/api/admin/reject/{token}",
    response_class=HTMLResponse,
)
def reject_user(
    token: str,
) -> HTMLResponse:

    data = verify_approval_token(
        token
    )

    if data is None:
        return HTMLResponse(
            content="""
            <h2>Invalid or expired rejection link.</h2>
            """,
            status_code=400,
        )

    if data["action"] != "reject":
        return HTMLResponse(
            content="""
            <h2>Invalid rejection action.</h2>
            """,
            status_code=400,
        )

    from auth_database import get_user_by_id

    user = get_user_by_id(
        data["user_id"]
    )

    if user is None:
        return HTMLResponse(
            content="""
            <h2>User not found.</h2>
            """,
            status_code=404,
        )

    if user["status"] != "pending":
        status = html.escape(
            str(user["status"])
        )

        return HTMLResponse(
            content=f"""
            <h2>This account has already been processed.</h2>
            <p>Current status: <strong>{status}</strong></p>
            """,
            status_code=200,
        )

    updated_user = set_user_status(
        data["user_id"],
        "rejected",
    )

    if updated_user is None:
        return HTMLResponse(
            content="""
            <h2>Could not reject the user.</h2>
            """,
            status_code=500,
        )

    return HTMLResponse(
        content="""
        <h2>Account rejected.</h2>
        <p>The user cannot log in.</p>
        """,
        status_code=200,
    )
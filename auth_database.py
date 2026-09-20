# auth_database.py

from dotenv import load_dotenv

load_dotenv(".env.local")

import os
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import psycopg
from psycopg.rows import dict_row


# ============================================================================
# DATABASE CONFIGURATION
# ============================================================================

DATABASE_URL = os.getenv("DATABASE_URL")


def _require_database_url() -> str:
    """
    Return DATABASE_URL from environment.

    The application must provide DATABASE_URL through the environment.
    Never hardcode database credentials into the source code.
    """

    if not DATABASE_URL:
        raise RuntimeError(
            "DATABASE_URL environment variable is not configured."
        )

    return DATABASE_URL


# ============================================================================
# DATABASE CONNECTION
# ============================================================================

def get_connection():
    """
    Open a PostgreSQL connection using Railway's DATABASE_URL.
    """

    return psycopg.connect(
        _require_database_url(),
        row_factory=dict_row,
    )


# ============================================================================
# DATABASE INITIALIZATION
# ============================================================================

def create_tables() -> None:
    """
    Create authentication tables if they do not already exist.

    Tables:
        users
        sessions
    """

    with get_connection() as connection:
        with connection.cursor() as cursor:

            # ----------------------------------------------------------------
            # USERS
            # ----------------------------------------------------------------

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id UUID PRIMARY KEY,
                    name TEXT NOT NULL,
                    surname TEXT NOT NULL,
                    email TEXT NOT NULL,
                    password_hash TEXT NOT NULL,

                    status TEXT NOT NULL
                        CHECK (
                            status IN (
                                'pending',
                                'approved',
                                'rejected'
                            )
                        ),

                    created_at TIMESTAMPTZ NOT NULL
                        DEFAULT CURRENT_TIMESTAMP,

                    approved_at TIMESTAMPTZ NULL
                )
                """
            )

            # ----------------------------------------------------------------
            # UNIQUE EMAIL
            # ----------------------------------------------------------------
            #
            # Email comparison is case-insensitive.
            #
            # Example:
            #
            # john@example.com
            # JOHN@EXAMPLE.COM
            #
            # are treated as the same account.
            #

            cursor.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS
                users_email_lower_unique
                ON users (LOWER(email))
                """
            )

            # ----------------------------------------------------------------
            # SESSIONS
            # ----------------------------------------------------------------

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    id UUID PRIMARY KEY,
                    user_id UUID NOT NULL,

                    token_hash TEXT NOT NULL,

                    created_at TIMESTAMPTZ NOT NULL
                        DEFAULT CURRENT_TIMESTAMP,

                    expires_at TIMESTAMPTZ NOT NULL,

                    CONSTRAINT sessions_user_fk
                        FOREIGN KEY (user_id)
                        REFERENCES users(id)
                        ON DELETE CASCADE
                )
                """
            )

            # ----------------------------------------------------------------
            # SESSION TOKEN INDEX
            # ----------------------------------------------------------------

            cursor.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS
                sessions_token_hash_unique
                ON sessions (token_hash)
                """
            )

            # ----------------------------------------------------------------
            # SESSION USER INDEX
            # ----------------------------------------------------------------

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS
                sessions_user_id_idx
                ON sessions (user_id)
                """
            )

        connection.commit()


# ============================================================================
# DATABASE HEALTH CHECK
# ============================================================================

def database_health_check() -> bool:
    """
    Verify that PostgreSQL is reachable.
    """

    try:
        with get_connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                result = cursor.fetchone()

                return result is not None

    except Exception as error:
        print(
            f"DATABASE HEALTH CHECK FAILED: {error}"
        )

        return False


# ============================================================================
# USER HELPERS
# ============================================================================

def normalize_email(email: str) -> str:
    """
    Normalize email before storage/search.
    """

    return str(email).strip().lower()


def create_user(
    name: str,
    surname: str,
    email: str,
    password_hash: str,
) -> Dict[str, Any]:

    user_id = uuid.uuid4()

    normalized_email = normalize_email(email)

    with get_connection() as connection:
        with connection.cursor() as cursor:

            cursor.execute(
                """
                INSERT INTO users (
                    id,
                    name,
                    surname,
                    email,
                    password_hash,
                    status
                )
                VALUES (
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    'pending'
                )
                RETURNING
                    id,
                    name,
                    surname,
                    email,
                    status,
                    created_at,
                    approved_at
                """,
                (
                    user_id,
                    str(name).strip(),
                    str(surname).strip(),
                    normalized_email,
                    password_hash,
                ),
            )

            user = cursor.fetchone()

        connection.commit()

    return dict(user)


def get_user_by_email(
    email: str,
) -> Optional[Dict[str, Any]]:

    normalized_email = normalize_email(email)

    with get_connection() as connection:
        with connection.cursor() as cursor:

            cursor.execute(
                """
                SELECT
                    id,
                    name,
                    surname,
                    email,
                    password_hash,
                    status,
                    created_at,
                    approved_at
                FROM users
                WHERE LOWER(email) = LOWER(%s)
                LIMIT 1
                """,
                (normalized_email,),
            )

            user = cursor.fetchone()

    if user is None:
        return None

    return dict(user)


def get_user_by_id(
    user_id: str,
) -> Optional[Dict[str, Any]]:

    with get_connection() as connection:
        with connection.cursor() as cursor:

            cursor.execute(
                """
                SELECT
                    id,
                    name,
                    surname,
                    email,
                    password_hash,
                    status,
                    created_at,
                    approved_at
                FROM users
                WHERE id = %s
                LIMIT 1
                """,
                (user_id,),
            )

            user = cursor.fetchone()

    if user is None:
        return None

    return dict(user)


# ============================================================================
# USER STATUS
# ============================================================================

def set_user_status(
    user_id: str,
    status: str,
) -> Optional[Dict[str, Any]]:

    allowed_statuses = {
        "pending",
        "approved",
        "rejected",
    }

    if status not in allowed_statuses:
        raise ValueError(
            f"Invalid user status: {status}"
        )

    approved_at = (
        datetime.now(timezone.utc)
        if status == "approved"
        else None
    )

    with get_connection() as connection:
        with connection.cursor() as cursor:

            cursor.execute(
                """
                UPDATE users
                SET
                    status = %s,
                    approved_at = %s
                WHERE id = %s
                RETURNING
                    id,
                    name,
                    surname,
                    email,
                    status,
                    created_at,
                    approved_at
                """,
                (
                    status,
                    approved_at,
                    user_id,
                ),
            )

            user = cursor.fetchone()

        connection.commit()

    if user is None:
        return None

    return dict(user)


# ============================================================================
# SESSION TOKEN HASHING
# ============================================================================

def hash_session_token(
    token: str,
) -> str:
    """
    Hash the raw session token before storing it in PostgreSQL.

    The raw session token itself is never stored in the database.
    """

    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


# ============================================================================
# SESSION CREATION
# ============================================================================

def create_session(
    user_id: str,
    token: str,
    expires_at: datetime,
) -> Dict[str, Any]:

    session_id = uuid.uuid4()

    token_hash = hash_session_token(token)

    with get_connection() as connection:
        with connection.cursor() as cursor:

            cursor.execute(
                """
                INSERT INTO sessions (
                    id,
                    user_id,
                    token_hash,
                    expires_at
                )
                VALUES (
                    %s,
                    %s,
                    %s,
                    %s
                )
                RETURNING
                    id,
                    user_id,
                    created_at,
                    expires_at
                """,
                (
                    session_id,
                    user_id,
                    token_hash,
                    expires_at,
                ),
            )

            session = cursor.fetchone()

        connection.commit()

    return dict(session)


# ============================================================================
# SESSION LOOKUP
# ============================================================================

def get_session_by_token(
    token: str,
) -> Optional[Dict[str, Any]]:

    token_hash = hash_session_token(token)

    with get_connection() as connection:
        with connection.cursor() as cursor:

            cursor.execute(
                """
                SELECT
                    sessions.id,
                    sessions.user_id,
                    sessions.created_at,
                    sessions.expires_at,

                    users.name,
                    users.surname,
                    users.email,
                    users.status

                FROM sessions

                INNER JOIN users
                    ON users.id = sessions.user_id

                WHERE sessions.token_hash = %s

                LIMIT 1
                """,
                (token_hash,),
            )

            session = cursor.fetchone()

    if session is None:
        return None

    return dict(session)


# ============================================================================
# SESSION DELETE
# ============================================================================

def delete_session(
    token: str,
) -> None:

    token_hash = hash_session_token(token)

    with get_connection() as connection:
        with connection.cursor() as cursor:

            cursor.execute(
                """
                DELETE FROM sessions
                WHERE token_hash = %s
                """,
                (token_hash,),
            )

        connection.commit()


# ============================================================================
# DELETE EXPIRED SESSIONS
# ============================================================================

def delete_expired_sessions() -> None:

    with get_connection() as connection:
        with connection.cursor() as cursor:

            cursor.execute(
                """
                DELETE FROM sessions
                WHERE expires_at <= CURRENT_TIMESTAMP
                """
            )

        connection.commit()


# ============================================================================
# DATABASE TEST
# ============================================================================

def initialize_auth_database() -> None:
    """
    Initialize authentication database and verify the connection.
    """

    print(
        "Connecting to authentication database..."
    )

    if not database_health_check():
        raise RuntimeError(
            "Unable to connect to PostgreSQL."
        )

    print(
        "PostgreSQL connection successful."
    )

    create_tables()

    print(
        "Authentication tables are ready."
    )


# ============================================================================
# DIRECT EXECUTION
# ============================================================================

if __name__ == "__main__":

    try:
        initialize_auth_database()

        print(
            "AUTH DATABASE INITIALIZATION COMPLETED."
        )

    except Exception as error:

        print(
            "AUTH DATABASE INITIALIZATION FAILED:"
        )

        print(
            error
        )

        raise
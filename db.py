import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "sumworth.db"
SCHEMA_PATH = BASE_DIR / "schema.sql"


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_connection()
    try:
        conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        # Older databases were created before token_version existed.
        columns = [r["name"] for r in conn.execute("PRAGMA table_info(users)")]
        if "token_version" not in columns:
            conn.execute(
                "ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0"
            )
        conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":
    init_db()
    print("Database ready:", DB_PATH)
